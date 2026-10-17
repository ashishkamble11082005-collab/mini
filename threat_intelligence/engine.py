from typing import Any, Iterable, Optional
from .attachment_analysis import analyze_attachment
from .url_reputation import analyze_url
from .virustotal import VirusTotalClient
from .local_url_intelligence import analyze_url_locally
from .local_attachment_intelligence import analyze_attachment_locally

class ThreatIntelligenceEngine:
    def __init__(self, client: Optional[VirusTotalClient] = None):
        self.client = client or VirusTotalClient()

    def analyze(self, urls: Optional[Iterable[str]] = None,
                attachments: Optional[Iterable[dict[str, Any]]] = None) -> dict[str, Any]:
        url_results = []

        for url in urls or []:
            local_result = analyze_url_locally(url)
            vt_result = analyze_url(url, self.client)

            url_results.append({
        "url": url,
        "local_intelligence": local_result,
        "virustotal": vt_result,
    })
        attachment_results = []

        for attachment in attachments or []:
            local_result = analyze_attachment_locally(
            attachment.get("filename"),
            attachment.get("content_type"),
    )

            vt_result = analyze_attachment(
         data=attachment.get("data", b""),
         filename=attachment.get("filename"),
         content_type=attachment.get("content_type"),
         client=self.client,
    )

            attachment_results.append({
         "filename": attachment.get("filename"),
         "local_intelligence": local_result,
         "virustotal": vt_result,
    })

        findings = []

        for r in url_results:
            local = r["local_intelligence"]
            vt = r["virustotal"]

            for finding in local.get("findings", []):
                findings.append({
                    "type": finding["type"],
                    "severity": finding["severity"],
                    "value": r["url"],
                    "reason": finding["reason"],
                    "source": "LOCAL",
                })

            if vt.get("risk") == "MALICIOUS":
                findings.append({
                    "type": "malicious_url",
                    "severity": "HIGH",
                    "value": r["url"],
                    "reason": "VirusTotal reported malicious detections for the URL",
                    "source": "VIRUSTOTAL",
                })
            elif vt.get("risk") == "SUSPICIOUS":
                findings.append({
                    "type": "suspicious_url",
                    "severity": "MEDIUM",
                    "value": r["url"],
                    "reason": "VirusTotal reported suspicious detections for the URL",
                    "source": "VIRUSTOTAL",
                })

        for r in attachment_results:
            local = r["local_intelligence"]
            vt = r["virustotal"]

            for finding in local.get("findings", []):
                findings.append({
                    "type": finding["type"],
                    "severity": finding["severity"],
                    "value": r["filename"],
                    "reason": finding["reason"],
                    "source": "LOCAL",
                })

            if vt.get("risk") == "MALICIOUS":
                findings.append({
                    "type": "malicious_attachment",
                    "severity": "HIGH",
                    "value": r["filename"],
                    "sha256": vt.get("sha256"),
                    "reason": "VirusTotal reported malicious detections for the attachment hash",
                    "source": "VIRUSTOTAL",
                })
            elif vt.get("risk") == "SUSPICIOUS":
                findings.append({
                    "type": "suspicious_attachment",
                    "severity": "MEDIUM",
                    "value": r["filename"],
                    "sha256": vt.get("sha256"),
                    "reason": "VirusTotal reported suspicious detections for the attachment hash",
                    "source": "VIRUSTOTAL",
                })

        degraded_statuses = {
            "UNAVAILABLE",
            "RATE_LIMITED",
            "UNAUTHORIZED",
            "ERROR",
        }

        degraded = any(
            r.get("status") in degraded_statuses
            for r in [
                *(r["virustotal"] for r in url_results),
                *(r["virustotal"] for r in attachment_results),
            ]
        )

        return {
            "status": (
                "DISABLED"
                if not self.client.enabled
                else "DEGRADED"
                if degraded
                else "OK"
            ),
            "urls": url_results,
            "attachments": attachment_results,
            "findings": findings,
            "summary": {
                "url_count": len(url_results),
                "attachment_count": len(attachment_results),
                "local_findings": sum(
                    len(r["local_intelligence"].get("findings", []))
                    for r in url_results
                ) + sum(
                    len(r["local_intelligence"].get("findings", []))
                    for r in attachment_results
                ),
                "malicious_urls": sum(
                    r["virustotal"].get("risk") == "MALICIOUS"
                    for r in url_results
                ),
                "suspicious_urls": sum(
                    r["virustotal"].get("risk") == "SUSPICIOUS"
                    for r in url_results
                ),
                "malicious_attachments": sum(
                    r["virustotal"].get("risk") == "MALICIOUS"
                    for r in attachment_results
                ),
                "suspicious_attachments": sum(
                    r["virustotal"].get("risk") == "SUSPICIOUS"
                    for r in attachment_results
                ),
            },
        }