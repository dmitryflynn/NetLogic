"""Manual NVD parser smoke script.

This file intentionally contains no unittest cases so automated discovery can
import it safely. Run it manually to exercise `_parse_nvd_item` against a live
NVD response when internet access is available.
"""

import json
import traceback
import urllib.error
import urllib.request

from src.nvd_lookup import _parse_nvd_item


def main():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache%20HTTP%20Server&resultsPerPage=1"
    req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/2.0"})
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.URLError as exc:
        print(f"NVD request unavailable: {exc}")
        return
    data = json.loads(resp.read())
    print("Keys:", data.keys())
    item = data.get("vulnerabilities", [])[0]
    try:
        _parse_nvd_item(item)
        print("Parsed!")
    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()
