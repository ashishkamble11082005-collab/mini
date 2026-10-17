from __future__ import annotations

from typing import Any, Optional
from integration.attachment_consistency import analyze_attachment_consistency
from email_parser import EmailParser
from authentication.analyzer import analyze_authentication
from threat_intelligence.engine import ThreatIntelligenceEngine
from ai_detector.predictor import EmailAIDetector


class ShieldMailPipeline:
    """
    Main orchestration layer for ShieldMail.

    Flow:
        Raw .eml
            ↓
        Parser
            ↓
        Authentication
            ↓
        Threat Intelligence
            ↓
        AI Detection
            ↓
        Final Decision
    """

    def __init__(self) -> None:
        self.parser = EmailParser()
        self.threat_engine = ThreatIntelligenceEngine()
        self.ai_detector = EmailAIDetector()

    # ---------------------------------------------------------
    # Final ShieldMail Decision Engine
    # ---------------------------------------------------------

    @staticmethod
    def _make_decision(
        authentication: dict[str, Any],
        threat_intelligence: dict[str, Any],
        ai_detection: dict[str, Any],
    ) -> dict[str, Any]:

        risk_score = float(ai_detection.get("risk_score", 0.0))
        risk_level = str(ai_detection.get("risk_level", "LOW"))

        reasons: list[str] = []

        # -----------------------------------------------------
        # Authentication
        # -----------------------------------------------------

        spf_status = str(
            authentication.get("spf", {}).get("status", "NONE")
        ).upper()

        dkim_status = str(
            authentication.get("dkim", {}).get("status", "NONE")
        ).upper()

        dmarc_status = str(
            authentication.get("dmarc", {}).get("status", "NONE")
        ).upper()

        # Authentication FAIL is meaningful.
        # NONE is not treated as failure.
        auth_failures = []

        if spf_status == "FAIL":
            auth_failures.append("SPF failed")

        if dkim_status == "FAIL":
            auth_failures.append("DKIM verification failed")

        if dmarc_status == "FAIL":
            auth_failures.append("DMARC failed")

        if auth_failures:
            reasons.extend(auth_failures)

        # -----------------------------------------------------
        # Threat Intelligence
        # -----------------------------------------------------

        malicious_urls = int(
            threat_intelligence.get("summary", {}).get(
                "malicious_urls", 0
            )
        )

        suspicious_urls = int(
            threat_intelligence.get("summary", {}).get(
                "suspicious_urls", 0
            )
        )

        malicious_attachments = int(
            threat_intelligence.get("summary", {}).get(
                "malicious_attachments", 0
            )
        )

        suspicious_attachments = int(
            threat_intelligence.get("summary", {}).get(
                "suspicious_attachments", 0
            )
        )

        if malicious_urls > 0:
            reasons.append(
                f"{malicious_urls} malicious URL(s) detected"
            )

        if suspicious_urls > 0:
            reasons.append(
                f"{suspicious_urls} suspicious URL(s) detected"
            )

        if malicious_attachments > 0:
            reasons.append(
                f"{malicious_attachments} malicious attachment(s) detected"
            )

        if suspicious_attachments > 0:
            reasons.append(
                f"{suspicious_attachments} suspicious attachment(s) detected"
            )

        # -----------------------------------------------------
        # AI evidence
        # -----------------------------------------------------

        ai_factors = ai_detection.get("contributing_factors", [])

        if isinstance(ai_factors, list):
            reasons.extend(str(factor) for factor in ai_factors)

        # -----------------------------------------------------
        # Determine final decision
        # -----------------------------------------------------

        # Strong external threat intelligence evidence takes
        # precedence over a lower ML confidence score.
        if malicious_urls > 0 or malicious_attachments > 0:
            final_decision = "QUARANTINE"
            final_level = "CRITICAL"

            risk_score = max(risk_score, 85.0)

        elif suspicious_attachments > 0:
            final_decision = "QUARANTINE"
            final_level = "HIGH"

            risk_score = max(risk_score, 70.0)

        elif risk_score >= 80.0:
            final_decision = "QUARANTINE"
            final_level = "CRITICAL"

        elif risk_score >= 60.0:
            final_decision = "WARN"
            final_level = "HIGH"

        elif risk_score >= 35.0:
            final_decision = "WARN"
            final_level = "MEDIUM"

        else:
            final_decision = "DELIVER"
            final_level = "LOW"

        # -----------------------------------------------------
        # Remove duplicate reasons while preserving order
        # -----------------------------------------------------

        unique_reasons = list(dict.fromkeys(reasons))

        return {
    "risk_score": round(float(risk_score), 2),
    "risk_level": final_level,
    "recommended_action": final_decision,
    "user_action": "NONE",
    "reasons": unique_reasons,
    }

    def analyze(
        self,
        raw_bytes: bytes,
        sender_ip: Optional[str] = None,
        helo: Optional[str] = None,
        envelope_from: Optional[str] = None,
        envelope_to: Optional[list[str]] = None,
    ) -> dict[str, Any]:

        # ---------------------------------------------------------
        # 1. Parse email
        # ---------------------------------------------------------

        parsed = self.parser.parse_bytes(raw_bytes)

        # ---------------------------------------------------------
        # 2. Authentication analysis
        # ---------------------------------------------------------

        authentication = analyze_authentication(
            raw_bytes=raw_bytes,
            sender_ip=sender_ip,
            helo=helo,
            envelope_from=envelope_from,
            envelope_to=envelope_to,
        )

        # ---------------------------------------------------------
        # 3. Extract URLs for Threat Intelligence
        # ---------------------------------------------------------

        urls = []

        for url in parsed.urls:
            value = getattr(url, "url", None)

            if value:
                urls.append(value)

        # ---------------------------------------------------------
        # 4. Threat Intelligence
        #
        # Prepare attachment metadata and raw payloads for Threat Intelligence.
        # ---------------------------------------------------------

        attachments = []

        for attachment in parsed.attachments:
            attachments.append({
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "data": attachment.data,
           })

        threat_intelligence = self.threat_engine.analyze(
           urls=urls,
           attachments=attachments,
        )

        # ---------------------------------------------------------
        # 5. AI Detection
        # ---------------------------------------------------------

        ai_detection_model = self.ai_detector.predict(parsed, authentication)

        ai_detection = ai_detection_model.model_dump()

                # Additional evidence: email body vs. PDF attachment content
        consistency_findings = analyze_attachment_consistency(
            parsed.body_text,
            parsed.attachments,
        )

        if consistency_findings:
            factors = ai_detection.get("contributing_factors", [])
            factors.extend(
                finding["reason"] for finding in consistency_findings
            )
            ai_detection["contributing_factors"] = factors

            # Supporting evidence only; do not automatically quarantine.
            ai_detection["risk_score"] = min(
                100.0,
                float(ai_detection.get("risk_score", 0.0)) + 15.0,
            )

        # Convert enum to normal JSON string
        if hasattr(ai_detection.get("risk_level"), "value"):
            ai_detection["risk_level"] = ai_detection["risk_level"].value

        # ---------------------------------------------------------
        # 6. Final ShieldMail Decision
        # ---------------------------------------------------------

        decision = self._make_decision(
            authentication=authentication,
            threat_intelligence=threat_intelligence,
            ai_detection=ai_detection,
        )

        # ---------------------------------------------------------
        # 7. Unified result
        # ---------------------------------------------------------

        return {
            "authentication": authentication,

            "threat_intelligence": threat_intelligence,

            "ai_detection": ai_detection,

            "risk_assessment": decision,

            "parsing": {
                "errors": parsed.parsing_errors,
                "url_count": len(parsed.urls),
                "attachment_count": len(parsed.attachments),
            },
            "attachment_consistency": consistency_findings,
        }