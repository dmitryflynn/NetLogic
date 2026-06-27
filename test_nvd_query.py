"""Manual live NVD query smoke script.

This file is import-safe for unittest discovery. Run it manually when you want
to test the NVD query path against the real API.
"""

from src.nvd_lookup import query_nvd_for_product


def mock_nvd_request(params):
    print("Called with:", params)
    import json
    import urllib.parse
    import urllib.request

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "NetLogic/2.0"})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as exc:
        print("Error in request:", exc)
        return None


def main():
    import src.nvd_lookup

    src.nvd_lookup._nvd_request = mock_nvd_request
    cves = query_nvd_for_product("apache")
    print("Found NVD CVEs:", len(cves))


if __name__ == "__main__":
    main()
