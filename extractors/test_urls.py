"""Remote source for the admin "Test Extractors" panel links.

The JSON (in this repo) maps each extractor key to a real sample URL,
e.g. {"voe": "https://voe.sx/e/xxxx", "mixdrop": ""}.
Edit extractors/extractor_test_urls.json to update links without redeploying.
"""

REMOTE_TEST_URLS_URL = (
    "https://raw.githubusercontent.com/realbestia1/EasyProxy/"
    "refs/heads/main/extractors/extractor_test_urls.json"
)
