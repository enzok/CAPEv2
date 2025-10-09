import json
import logging
from pathlib import Path

import requests
import urllib3
from urllib3.exceptions import InsecureRequestWarning

from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

integrations_conf = Config("integrations")
BASE_URL = "https://csbapi.zscalertwo.net"
APIKEY = integrations_conf.zscaler.apikey
urllib3.disable_warnings(InsecureRequestWarning)

class ZscalerClient:
    def __init__(self, api_key: str = APIKEY, base_url: str = BASE_URL):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def submit_file(self, filepath: str, force: bool = True) -> dict:
        """
        Submit a file to Zscaler Sandbox for analysis.
        """
        url = f"{self.base_url}/zscsb/submit?force={'1' if force else '0'}&api_token={self.api_key}"
        try:
            with open(filepath, "rb") as f:
                resp = requests.post(url, data=f, verify=False)

            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError:
            return None

    def get_report(self, sha256: str, details: str = "summary") -> dict:
        """
        Retrieve sandbox report for a given hash.
        """
        url = f"{self.base_url}/sandbox/report/{sha256}?details={details}&api_token={self.api_key}"
        try:
            resp = requests.get(url, verify=False)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            return e.response.content

    def save_report_json(self, sha256: str, report: dict, outdir: str = "downloads") -> str:
        """
        Save Zscaler JSON report locally.
        """
        folder = Path(outdir) / sha256 / "Zscaler"
        folder.mkdir(parents=True, exist_ok=True)
        outfile = folder / "report.json"
        with open(outfile, "w") as f:
            json.dump(report, f, indent=2)

        return str(outfile)


def zscaler_lookup(sha256: str = None):
    if not integrations_conf.zscaler.enabled:
        return None

    zclient = ZscalerClient()
    if zclient:
        return zclient.get_report(sha256=sha256)

    return None


def zscaler_dl_report(sha256: str, details: str = "summary") -> dict:
    if not integrations_conf.zscaler.enabled:
        return None

    zclient = ZscalerClient()
    if zclient:
        return zclient.get_report(sha256=sha256, details=details)

    return None


if __name__ == "__main__":
    import sys

    sha256 = sys.argv[1]
    client = ZscalerClient()

    if client:
        result = client.get_report(sha256)
        if result:
            print(result)
