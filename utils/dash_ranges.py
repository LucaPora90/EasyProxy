"""Resolve flat SIDX indexes into explicit DASH byte-range segments."""
import copy
import re
import struct
import xml.etree.ElementTree as ET
from urllib.parse import urljoin


def parse_range(value):
    if not re.fullmatch(r"\d+-\d+", value or ""):
        raise ValueError("Invalid DASH byte range")
    start, end = map(int, value.split("-"))
    if end < start:
        raise ValueError("Reversed DASH byte range")
    return start, end


async def fetch_range(session, url, headers, value, limit=64 * 1024 * 1024):
    start, end = parse_range(value)
    size = end - start + 1
    if size > limit:
        raise ValueError("DASH range exceeds size limit")
    request_headers = {k: v for k, v in headers.items() if k.lower() not in ('range', 'accept-encoding')}
    request_headers.update({'Range': f'bytes={start}-{end}', 'Accept-Encoding': 'identity'})
    async with session.get(url, headers=request_headers, allow_redirects=False, timeout=30) as response:
        if response.status != 206:
            raise ValueError(f"DASH source did not honor Range: {response.status}")
        match = re.fullmatch(r'bytes (\d+)-(\d+)/(?:\d+|\*)', response.headers.get('Content-Range', ''))
        if not match or tuple(map(int, match.groups())) != (start, end):
            raise ValueError("DASH Content-Range mismatch")
        data = bytearray()
        async for chunk in response.content.iter_chunked(65536):
            data.extend(chunk)
            if len(data) > size:
                raise ValueError("Oversized DASH range response")
        if len(data) != size:
            raise ValueError("Truncated DASH range response")
        return bytes(data)


def parse_sidx(data, absolute_start):
    pos = 0
    while pos + 8 <= len(data):
        size, kind = struct.unpack_from('>I4s', data, pos)
        header = 8
        if size == 1:
            if pos + 16 > len(data):
                raise ValueError('Truncated SIDX header')
            size = struct.unpack_from('>Q', data, pos + 8)[0]
            header = 16
        if size < header or pos + size > len(data):
            raise ValueError('Invalid SIDX box size')
        if kind != b'sidx':
            pos += size
            continue
        payload = data[pos + header:pos + size]
        try:
            version = payload[0]
            timescale = struct.unpack_from('>I', payload, 8)[0]
            if not timescale or version not in (0, 1):
                raise ValueError('Unsupported SIDX version/timescale')
            fmt = '>QQ' if version else '>II'
            earliest, offset = struct.unpack_from(fmt, payload, 12)
            cursor = 28 if version else 20
            count = struct.unpack_from('>H', payload, cursor + 2)[0]
            cursor += 4
            byte_pos = absolute_start + pos + size + offset
            segments = []
            for _ in range(count):
                reference, duration, sap = struct.unpack_from('>III', payload, cursor)
                cursor += 12
                if reference & 0x80000000:
                    raise ValueError('Hierarchical SIDX indexes are unsupported')
                length = reference & 0x7fffffff
                if not length or not duration:
                    raise ValueError('Empty SIDX reference')
                segments.append((byte_pos, byte_pos + length - 1, earliest, duration))
                byte_pos += length
                earliest += duration
            if not segments:
                raise ValueError('Empty SIDX index')
            return timescale, segments
        except (IndexError, struct.error) as exc:
            raise ValueError('Truncated SIDX index') from exc
    raise ValueError('SIDX box missing')


async def expand_segment_bases(xml, mpd_url, fetch, only_rep_id=None):
    root = ET.fromstring(xml)
    ns = root.tag.split('}')[0] + '}' if '}' in root.tag else ''

    async def walk(node, base, inherited=None):
        b = node.find(ns + 'BaseURL')
        if b is not None and b.text:
            base = urljoin(base, b.text.strip())
        own = node.find(ns + 'SegmentBase')
        effective = copy.deepcopy(inherited)
        if own is not None:
            if effective is None:
                effective = copy.deepcopy(own)
            else:
                effective.attrib.update(own.attrib)
                for child in own:
                    for old in effective.findall(child.tag):
                        effective.remove(old)
                    effective.append(copy.deepcopy(child))
        if node.find(ns + 'SegmentTemplate') is not None or node.find(ns + 'SegmentList') is not None:
            effective = None
        if (
            node.tag == ns + 'Representation'
            and effective is not None
            and (only_rep_id is None or node.get('id') == only_rep_id)
        ):
            index_range = effective.get('indexRange')
            start, _ = parse_range(index_range)
            scale, segments = parse_sidx(await fetch(base, index_range), start)
            listing = ET.Element(ns + 'SegmentList', timescale=str(scale))
            pto = int(effective.get('presentationTimeOffset', '0'))
            old_scale = int(effective.get('timescale', '1'))
            if old_scale <= 0 or (pto * scale) % old_scale:
                raise ValueError('Unrepresentable DASH presentation offset')
            listing.set('presentationTimeOffset', str(pto * scale // old_scale))
            init = effective.find(ns + 'Initialization')
            if init is None:
                raise ValueError('SegmentBase initialization missing')
            init = copy.deepcopy(init)
            init.set('sourceURL', urljoin(base, init.get('sourceURL', '')))
            listing.append(init)
            timeline = ET.SubElement(listing, ns + 'SegmentTimeline')
            for first, last, timestamp, duration in segments:
                ET.SubElement(timeline, ns + 'S', t=str(timestamp), d=str(duration))
                ET.SubElement(listing, ns + 'SegmentURL', media=base, mediaRange=f'{first}-{last}')
            node.append(listing)
        for child in list(node):
            if child.tag in (ns + 'Period', ns + 'AdaptationSet', ns + 'Representation'):
                await walk(child, base, effective)
        if own is not None:
            node.remove(own)

    await walk(root, mpd_url)
    return ET.tostring(root, encoding='unicode')
