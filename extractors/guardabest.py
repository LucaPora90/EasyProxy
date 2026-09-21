from extractors.f16px import F16PxExtractor


class GuardabestExtractor(F16PxExtractor):
    """Guardabest/Byse embed extractor."""

    ERROR_PREFIX = "GUARDABEST"

    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies)
        self.extractor_name = "guardabest"
