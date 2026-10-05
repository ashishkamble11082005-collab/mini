"""
Main Entrypoint Script for Email Parser & AI Threat Detection Pipeline.

Usage:
    python mini/main.py mini/tests/fixtures/phishing_defanged.eml
    python mini/main.py mini/tests/fixtures/phishing_defanged.eml --json
"""

import argparse
import json
import sys
from pathlib import Path

# Reconfigure stdout to UTF-8 for Windows console support
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add mini directory to sys.path so it can be run from any working directory
mini_dir = Path(__file__).resolve().parent
if str(mini_dir) not in sys.path:
    sys.path.insert(0, str(mini_dir))

from ai_detector import EmailAIDetector
from email_parser import EmailParser


def analyze_email(file_path: str) -> dict:
    """Parses email file and runs AI threat detector, returning consolidated result dict."""
    parser = EmailParser()
    detector = EmailAIDetector()

    parsed_result = parser.parse_file(file_path)
    detection_output = detector.predict(parsed_result)

    return {
        "file_path": str(file_path),
        "parsed_email": parsed_result.model_dump(),
        "ai_detection": detection_output.model_dump(),
    }


def main():
    cli_parser = argparse.ArgumentParser(
        description="Run complete Email Parser & AI Threat Detector pipeline on an .eml file."
    )
    cli_parser.add_argument(
        "file",
        nargs="?",
        default=str(mini_dir / "tests" / "fixtures" / "phishing_defanged.eml"),
        help="Path to .eml file (defaults to sample phishing fixture)",
    )
    cli_parser.add_argument(
        "--json", action="store_true", help="Output full consolidated JSON payload"
    )
    args = cli_parser.parse_args()

    result = analyze_email(args.file)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        ai = result["ai_detection"]
        hdrs = result["parsed_email"]["headers"]
        print("=" * 65)
        print(" EMAIL PARSER & AI THREAT DETECTION ANALYSIS REPORT")
        print("=" * 65)
        print(f" Target File        : {args.file}")
        print(f" Subject            : {hdrs.get('subject')}")
        print(f" Sender             : {hdrs.get('sender', {}).get('raw') if hdrs.get('sender') else 'N/A'}")
        print(f" Parse Time         : {result['parsed_email']['parse_duration_ms']} ms")
        print("-" * 65)
        print(f" AI Threat Flag     : {'[ALERT] THREAT DETECTED' if ai['is_threat'] else '[CLEAN] CLEAN EMAIL'}")
        print(f" Confidence Score   : {ai['confidence_score'] * 100:.2f}%")
        print(f" Hybrid Risk Score  : {ai['risk_score']} / 100.0 [{ai['risk_level']}]")
        print(f" Inference Time     : {ai['inference_time_ms']} ms")
        print("-" * 65)
        if ai["contributing_factors"]:
            print(" Risk Trigger Factors:")
            for factor in ai["contributing_factors"]:
                print(f"   * {factor}")
        else:
            print(" Risk Trigger Factors: None")
        print("=" * 65)


if __name__ == "__main__":
    main()
