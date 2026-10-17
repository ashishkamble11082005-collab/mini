from __future__ import annotations

import base64
import os
from dotenv import load_dotenv

load_dotenv()

from typing import Any, Optional

import requests


class VirusTotalError(Exception):
    pass


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 15):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        if not self.enabled:
            raise VirusTotalError("VirusTotal API key is not configured")
        return {"x-apikey": self.api_key, "accept": "application/json"}

    @staticmethod
    def url_id(url: str) -> str:
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
        return encoded.rstrip("=")

    @staticmethod
    def _stats(attributes: dict[str, Any]) -> dict[str, int]:
        stats = attributes.get("last_analysis_stats") or {}
        return {k: int(stats.get(k, 0) or 0) for k in
                ("malicious", "suspicious", "undetected", "harmless", "timeout")}

    def _get(self, path: str):
        try:
            return requests.get(
                f"{self.BASE_URL}{path}",
                headers=self._headers(),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise VirusTotalError(f"VirusTotal request failed: {exc}") from exc

    def get_url_report(self, url: str) -> dict[str, Any]:
        if not url or not url.strip():
            return {"status": "INVALID", "url": url, "reason": "URL is empty"}

        response = self._get(f"/urls/{self.url_id(url.strip())}")

        if response.status_code == 404:
            return {"status": "NOT_FOUND", "url": url,
                    "reason": "No VirusTotal URL report was found"}
        if response.status_code in (401, 403):
            return {"status": "UNAUTHORIZED", "url": url,
                    "reason": "VirusTotal API key was rejected or lacks access"}
        if response.status_code == 429:
            return {"status": "RATE_LIMITED", "url": url,
                    "reason": "VirusTotal API rate limit was reached"}
        if not response.ok:
            return {"status": "ERROR", "url": url,
                    "http_status": response.status_code,
                    "reason": f"VirusTotal returned HTTP {response.status_code}"}

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = self._stats(attributes)
        return {
            "status": "FOUND",
            "url": url,
            "reputation": attributes.get("reputation"),
            "stats": stats,
            "malicious": stats["malicious"] > 0,
            "suspicious": stats["suspicious"] > 0,
            "categories": attributes.get("categories", {}),
            "last_final_url": attributes.get("last_final_url"),
            "times_submitted": attributes.get("times_submitted"),
            "scan_date": attributes.get("last_analysis_date"),
        }

    def get_file_report(self, sha256: str) -> dict[str, Any]:
        if not sha256:
            return {"status": "INVALID", "sha256": sha256,
                    "reason": "SHA-256 is empty"}

        sha256 = sha256.lower()
        response = self._get(f"/files/{sha256}")

        if response.status_code == 404:
            return {"status": "NOT_FOUND", "sha256": sha256,
                    "reason": "No VirusTotal file report was found for this hash"}
        if response.status_code in (401, 403):
            return {"status": "UNAUTHORIZED", "sha256": sha256,
                    "reason": "VirusTotal API key was rejected or lacks access"}
        if response.status_code == 429:
            return {"status": "RATE_LIMITED", "sha256": sha256,
                    "reason": "VirusTotal API rate limit was reached"}
        if not response.ok:
            return {"status": "ERROR", "sha256": sha256,
                    "http_status": response.status_code,
                    "reason": f"VirusTotal returned HTTP {response.status_code}"}

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = self._stats(attributes)
        return {
            "status": "FOUND",
            "sha256": sha256,
            "reputation": attributes.get("reputation"),
            "stats": stats,
            "malicious": stats["malicious"] > 0,
            "suspicious": stats["suspicious"] > 0,
            "type_description": attributes.get("type_description"),
            "size": attributes.get("size"),
            "names": attributes.get("names", []),
            "scan_date": attributes.get("last_analysis_date"),
        }

    def scan_url(self, url: str) -> dict[str, Any]:
        """Explicit URL submission; the engine does not call this automatically."""
        if not self.enabled:
            return {"status": "DISABLED", "url": url,
                    "reason": "VirusTotal API key is not configured"}
        try:
            response = requests.post(
                f"{self.BASE_URL}/urls",
                headers={**self._headers(),
                         "content-type": "application/x-www-form-urlencoded"},
                data={"url": url},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise VirusTotalError(f"VirusTotal URL submission failed: {exc}") from exc

        if response.status_code == 429:
            return {"status": "RATE_LIMITED", "url": url,
                    "reason": "VirusTotal API rate limit was reached"}
        if response.status_code in (401, 403):
            return {"status": "UNAUTHORIZED", "url": url,
                    "reason": "VirusTotal API key was rejected or lacks access"}
        if not response.ok:
            return {"status": "ERROR", "url": url,
                    "http_status": response.status_code,
                    "reason": f"VirusTotal returned HTTP {response.status_code}"}

        payload = response.json()
        return {"status": "SUBMITTED", "url": url,
                "analysis_id": payload.get("data", {}).get("id")}
