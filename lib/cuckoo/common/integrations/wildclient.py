import os
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Tuple

import requests

from lib.cuckoo.common.config import Config


integrations_conf = Config("integrations")
BASE_URL = "https://wildfire.paloaltonetworks.com/publicapi"
APIKEY = integrations_conf.wildfire.apikey

VERDICT_MAPPING = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    5: "C2",
    -100: "pending",
    -101: "error",
    -102: "unknown",
    -103: "invalid",
}


class WildFireClient:
    def __init__(self, api_key: str = APIKEY, base_url: str = BASE_URL, verify_ssl=True):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def submit_file(self, filepath: str) -> str:
        url = f"{self.base_url}/submit/file"
        try:
            with open(filepath, "rb") as f:
                files = {"file": (os.path.basename(filepath), f), "apikey": (None, self.api_key)}
                resp = self.session.post(url, files=files)

            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            sha256 = root.findtext(".//sha256")
            if not sha256:
                return None

        except requests.HTTPError:
            return None

        return sha256

    def submit_url(self, url_input: str) -> str:
        url = f"{self.base_url}/submit/url"
        files = {"url": (None, url_input), "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url, files=files)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            sha256 = root.findtext(".//sha256")
            if not sha256:
                return None

        except requests.HTTPError:
            return None

        return sha256

    def change_verdict(self, hash256: str, verdict: str) -> bool:
        url = f"{self.base_url}/submit/local-verdict-change"
        comment = "Change verdict from benign to malware."
        files = {"hash": (None, hash256), "verdict": verdict, "comment": comment, "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url, files=files)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            body = root.findtext(".//body")
            if not body:
                return False

            index = body.find("new verdict:1")
            if index != -1:
                return True

        except requests.HTTPError:
            return False

    def get_verdict(self, sha256: Optional[str] = None, url: Optional[str] = None) -> Optional[Dict]:
        url_endpoint = f"{self.base_url}/get/verdict"
        files = {"apikey": (None, self.api_key)}
        if sha256:
            files["hash"] = (None, sha256)

        if url:
            files["url"] = (None, url)

        try:
            resp = self.session.post(url_endpoint, files=files)
            resp.raise_for_status()
            root = ET.fromstring(resp.text)
            info = root.find(".//get-verdict-info")
            code = int(info.findtext("verdict", "-102"))
            result = {"verdict_code": code, "verdict_text": VERDICT_MAPPING.get(code, "unknown")}
            if url:
                result["url"] = info.findtext("url")
                result["analysis_time"] = info.findtext("analysis_time")
                result["valid"] = info.findtext("valid")

            return result
        except requests.HTTPError:
            return None

    def poll_verdict(self, sha256: Optional[str] = None, url: Optional[str] = None, interval=10, timeout=600):
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.get_verdict(sha256=sha256, url=url)
            if res and res.get("verdict_code", "") not in (-100, -102):
                return res

            time.sleep(interval)
        return None

    def get_report(self, sha256: str, fmt="pdf") -> bytes:
        url_endpoint = f"{self.base_url}/get/report"
        files = {"hash": (None, sha256), "format": (None, fmt), "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url_endpoint, files=files, stream=True)
            resp.raise_for_status()
            return resp.content

        except requests.HTTPError as e:
            return e.response.content

    def get_sample(self, sha256: str) -> Tuple[bytes, str]:
        url_endpoint = f"{self.base_url}/get/sample"
        files = {"hash": (None, sha256), "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url_endpoint, files=files, stream=True)
            resp.raise_for_status()
            return resp.content

        except requests.RequestException as e:
            return e.response.content

    def get_pcap(self, sha256: str) -> Tuple[bytes, str]:
        url_endpoint = f"{self.base_url}/get/pcap"
        files = {"hash": (None, sha256), "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url_endpoint, files=files, stream=True)
            resp.raise_for_status()
            return resp.content

        except requests.RequestException as e:
            return e.response.content

    def get_web_artifacts(self, sha256: str) -> Tuple[bytes, str]:
        url_endpoint = f"{self.base_url}/get/web-artifacts"
        files = {"hash": (None, sha256), "apikey": (None, self.api_key)}
        try:
            resp = self.session.post(url_endpoint, files=files, stream=True)
            resp.raise_for_status()
            return resp.content

        except requests.RequestException as e:
            return e.response.content


def wf_lookup(sha256: str = None, url: str = None):
    if not integrations_conf.wildfire.enabled:
        return None

    result = None
    wclient = WildFireClient()
    if wclient:
        if url:
            resp = wclient.poll_verdict(url=url, interval=5, timeout=30)
        else:
            resp = wclient.poll_verdict(sha256=sha256, interval=5, timeout=30)

        verdict = resp.get("verdict_text")
        if verdict and verdict.lower() != "unknown":
            result = verdict

        return result

    return result


def wf_dl_report(sha256: str = None):
    if not integrations_conf.wildfire.enabled:
        return None

    wclient = WildFireClient()
    if wclient:
        resp = wclient.get_report(sha256)
        return resp

    return None


def wf_dl_pcap(sha256: str = None):
    if not integrations_conf.wildfire.enabled:
        return None

    wclient = WildFireClient()
    if wclient:
        resp = wclient.get_pcap(sha256)
        return resp

    return None


def wf_change_verdict(sha256: str = None, verdict: str = "1"):
    if not integrations_conf.wildfire.enabled:
        return None

    wclient = WildFireClient()
    if wclient:
        resp = wclient.change_verdict(sha256, verdict)
        return resp

    return None


if __name__ == "__main__":
    import sys

    sha256 = sys.argv[1]

    result = wf_lookup(sha256)
    if result:
        print(result)
