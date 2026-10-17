from __future__ import annotations

import re
from pathlib import Path


DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com",
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".msi",
    ".jar", ".hta", ".iso", ".img",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm",
}

DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.[a-z0-9]{1,6}\.(exe|dll|scr|bat|cmd|js|jse|vbs|vbe|ps1|msi|jar|hta)$",
    re.IGNORECASE,
)


def analyze_attachment_locally(
    filename: str | None,
    content_type: str | None,
) -> dict:
    findings = []

    name = (filename or "").strip()
    content_type = (content_type or "").lower()

    if not name:
        return {
            "status": "ANALYZED",
            "risk": "NO_FINDINGS",
            "findings": [],
        }

    suffix = Path(name).suffix.lower()

    if suffix in DANGEROUS_EXTENSIONS:
        findings.append({
            "type": "dangerous_file_extension",
            "severity": "HIGH",
            "reason": f"Attachment uses a potentially executable file extension: {suffix}",
        })

    if suffix in MACRO_EXTENSIONS:
        findings.append({
            "type": "macro_enabled_document",
            "severity": "MEDIUM",
            "reason": f"Attachment is a macro-enabled Office document: {suffix}",
        })

    if DOUBLE_EXTENSION_PATTERN.search(name):
        findings.append({
            "type": "double_extension",
            "severity": "HIGH",
            "reason": "Filename uses a potentially deceptive double extension",
        })

    if suffix == ".exe" and content_type.startswith("text/"):
        findings.append({
            "type": "extension_content_mismatch",
            "severity": "HIGH",
            "reason": "Executable extension conflicts with the reported text MIME type",
        })

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    highest = max(
        (severity_rank[f["severity"]] for f in findings),
        default=0,
    )

    risk = {
        0: "NO_FINDINGS",
        1: "LOW",
        2: "MEDIUM",
        3: "HIGH",
    }[highest]

    return {
        "status": "ANALYZED",
        "risk": risk,
        "findings": findings,
    }