"""Self-update service for EasyProxy standalone and source installations."""
import asyncio
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
import aiohttp
from config import APP_VERSION

logger = logging.getLogger(__name__)

REPO_OWNER = "realbestia1"
REPO_NAME = "EasyProxy"
GITHUB_API_LATEST = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
GITHUB_RAW_CONFIG = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/main/config.py"
GITHUB_ZIP_DOWNLOAD = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/latest/download/EasyProxy-windows-amd64.zip"


def get_install_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def cleanup_old_update_files() -> None:
    """Removes leftover temporary files from previous updates."""
    try:
        install_dir = get_install_dir()
        for pattern in ("*.old", "_updater.bat", "temp_update.zip"):
            for f in install_dir.glob(pattern):
                try:
                    f.unlink(missing_ok=True)
                except OSError:
                    pass
    except Exception as exc:
        logger.debug("Failed to clean up old update files: %s", exc)


def parse_version_tuple(v_str: str) -> tuple[int, ...]:
    cleaned = re.sub(r"^[^\d]*", "", str(v_str).strip())
    numbers = []
    for part in re.split(r"[^\d]+", cleaned):
        if part.isdigit():
            numbers.append(int(part))
    return tuple(numbers) if numbers else (0,)


def is_newer_version(latest: str, current: str = APP_VERSION) -> bool:
    try:
        if str(latest).strip() in ("Checking...", "Unknown", "Error", "", "None"):
            return False
        return parse_version_tuple(latest) > parse_version_tuple(current)
    except Exception:
        return False


async def check_update_info() -> dict:
    """Fetch latest version from GitHub API or raw config fallback."""
    latest_ver = "Unknown"
    release_notes = ""
    download_url = GITHUB_ZIP_DOWNLOAD

    headers = {"User-Agent": f"EasyProxy/{APP_VERSION}", "Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=5)

    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            try:
                async with session.get(GITHUB_API_LATEST, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        tag = data.get("tag_name", "").lstrip("v")
                        if tag:
                            latest_ver = tag
                            release_notes = data.get("body", "")
                            for asset in data.get("assets", []):
                                if "windows-amd64" in asset.get("name", "").lower():
                                    download_url = asset.get("browser_download_url", download_url)
            except Exception as api_err:
                logger.debug("GitHub API release check failed, using raw fallback: %s", api_err)

            # Fallback to config.py if API rate-limited or failed
            if latest_ver == "Unknown":
                cb = int(time.time())
                raw_url = f"{GITHUB_RAW_CONFIG}?t={cb}"
                async with session.get(raw_url, headers=headers) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        m = re.search(r'APP_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                        if m:
                            latest_ver = m.group(1).lstrip("v")
    except Exception as exc:
        logger.debug("Update check error: %s", exc)

    return {
        "current_version": APP_VERSION,
        "latest_version": latest_ver,
        "update_available": is_newer_version(latest_ver, APP_VERSION) if latest_ver != "Unknown" else False,
        "download_url": download_url,
        "release_notes": release_notes,
        "is_docker": is_docker(),
    }


def is_docker() -> bool:
    return os.path.exists("/.dockerenv") or os.environ.get("DOCKER_CONTAINER") == "1"


def can_self_update() -> bool:
    """Return True only when running as a frozen standalone Windows executable."""
    return getattr(sys, "frozen", False) and os.name == "nt" and not is_docker()


async def apply_self_update() -> tuple[bool, str]:
    """Download update and restart application."""
    if is_docker():
        return False, (
            "EasyProxy è in esecuzione all'interno di un container Docker.\n"
            "Per aggiornarlo scarica la nuova immagine:\n"
            "docker pull ghcr.io/realbestia1/easyproxy:latest\n"
            "oppure usa Watchtower per aggiornamenti automatici."
        )

    if not getattr(sys, "frozen", False):
        # Running from source: git pull
        try:
            root = get_install_dir()
            proc = await asyncio.create_subprocess_exec(
                "git", "pull",
                cwd=str(root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                return True, "Aggiornato tramite git con successo. Riavvia l'applicazione."
            return False, f"Git pull fallito: {stderr.decode(errors='ignore')}"
        except Exception as exc:
            return False, f"Aggiornamento git fallito: {exc}"

    if os.name != "nt":
        return False, "Auto-aggiornamento binario supportato solo su Windows."

    info = await check_update_info()
    download_url = info.get("download_url") or GITHUB_ZIP_DOWNLOAD

    install_dir = get_install_dir()
    zip_dest = install_dir / "temp_update.zip"
    updater_bat = install_dir / "_updater.bat"

    logger.info("Downloading EasyProxy update from %s ...", download_url)
    try:
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(download_url) as resp:
                if resp.status != 200:
                    return False, f"Download aggiornamento fallito (HTTP {resp.status})"
                with open(zip_dest, "wb") as f:
                    while True:
                        chunk = await resp.content.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
    except Exception as exc:
        zip_dest.unlink(missing_ok=True)
        return False, f"Errore durante il download dell'aggiornamento: {exc}"

    # Generate detached batch updater script
    bat_content = f"""@echo off
setlocal enabledelayedexpansion
timeout /t 2 /nobreak >nul
set "DIR=%~dp0"
set "ZIP=%~dp0temp_update.zip"

taskkill /f /im EasyProxy.exe >nul 2>&1
taskkill /f /im flaresolverr.exe >nul 2>&1
taskkill /f /im tor.exe >nul 2>&1
taskkill /f /im torclient.exe >nul 2>&1
taskkill /f /im wireproxy.exe >nul 2>&1
taskkill /f /im lyrebird.exe >nul 2>&1

if exist "!DIR!EasyProxy.exe" (
    move /y "!DIR!EasyProxy.exe" "!DIR!EasyProxy.exe.old" >nul 2>&1
)
tar -xf "!ZIP!" -C "!DIR!" >nul 2>&1
del "!ZIP!" >nul 2>&1
del "!DIR!EasyProxy.exe.old" >nul 2>&1

start "" "!DIR!EasyProxy.exe"
del "%~f0"
"""
    try:
        updater_bat.write_text(bat_content, encoding="utf-8")
    except Exception as exc:
        zip_dest.unlink(missing_ok=True)
        return False, f"Impossibile creare lo script di aggiornamento: {exc}"

    logger.info("Spawning detached updater and shutting down...")
    DETACHED_PROCESS = 0x00000008
    try:
        subprocess.Popen(
            ["cmd.exe", "/c", str(updater_bat)],
            cwd=str(install_dir),
            creationflags=DETACHED_PROCESS,
            close_fds=True,
        )
    except Exception as exc:
        return False, f"Avvio updater fallito: {exc}"

    # Schedule exit after short delay to return HTTP response
    loop = asyncio.get_running_loop()
    loop.call_later(1.0, sys.exit, 0)
    return True, "Aggiornamento in corso... L'applicazione si riavvierà a breve."
