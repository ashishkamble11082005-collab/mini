"""
ShieldMail Authentication Analyzer

Integrates:
    - Authentication context extraction
    - SPF verification
    - DKIM verification
    - DMARC evaluation

This module orchestrates the existing authentication components.
It does not implement SPF, DKIM, or DMARC itself.
"""

from .spf import check_spf
from .dkim import verify_dkim
from .dmarc import check_dmarc
from authentication_extractor import extract_authentication_context


def analyze_authentication(
    raw_bytes: bytes,
    sender_ip=None,
    helo=None,
    envelope_from=None,
    envelope_to=None,
):
    """
    Analyze an email's SPF, DKIM, and DMARC authentication.

    Parameters
    ----------
    raw_bytes : bytes
        Original raw email bytes.

    sender_ip : str, optional
        Connecting SMTP sender IP address.

    helo : str, optional
        SMTP HELO/EHLO hostname.

    envelope_from : str, optional
        SMTP MAIL FROM address.

    envelope_to : list[str], optional
        SMTP RCPT TO addresses.

    Returns
    -------
    dict
        Unified authentication analysis result.
    """

    # ---------------------------------------------------------
    # 1. Extract authentication context from original email
    # ---------------------------------------------------------

    context = extract_authentication_context(
        raw_bytes=raw_bytes,
        sender_ip=sender_ip,
        helo=helo,
        envelope_from=envelope_from,
        envelope_to=envelope_to,
    )

    # ---------------------------------------------------------
    # 2. SPF
    # ---------------------------------------------------------

    spf_domain = context.envelope_from_domain
    if spf_domain:
     spf_result = check_spf(
        domain=spf_domain,
        sender_ip=context.sender_ip,
    )
    else:
     spf_result = {
        "status": "NONE",
        "domain": None,
        "reason": "No SMTP envelope-from domain available for SPF evaluation",
    }

    # ---------------------------------------------------------
    # 3. DKIM
    # ---------------------------------------------------------

    dkim_results = []

    for signature_header in context.dkim_signatures:
        try:
            result = verify_dkim(
                signature_header=signature_header,
                raw_headers=context.raw_headers_map,
                body=context.raw_body,
            )

            dkim_results.append(result)

        except Exception as exc:
            dkim_results.append(
                {
                    "status": "ERROR",
                    "reason": f"DKIM verification error: {exc}",
                }
            )

    # ---------------------------------------------------------
    # 4. Select DKIM result for DMARC
    # ---------------------------------------------------------
    #
    # DMARC can succeed if an aligned DKIM signature passes.
    # Therefore, do not simply assume the first signature is
    # the only relevant one.
    #
    # For the current integration, prefer a PASS result.
    # If there is no PASS result, retain the first result when
    # available so that DMARC still receives the DKIM evidence.
    # ---------------------------------------------------------

    dkim_result = None

    for result in dkim_results:
        if result.get("status") == "PASS":
            dkim_result = result
            break

    if dkim_result is None and dkim_results:
        dkim_result = dkim_results[0]

    if dkim_result is None:
        dkim_result = {
            "status": "NONE",
            "domain": None,
            "reason": "No DKIM signature was available for verification",
        }

    # ---------------------------------------------------------
    # 5. DMARC
    # ---------------------------------------------------------

    if context.from_domain:
        dmarc_result = check_dmarc(
            from_domain=context.from_domain,
            spf_result=spf_result,
            dkim_result=dkim_result,
        )
    else:
        dmarc_result = {
            "status": "NONE",
            "domain": None,
            "reason": "No From domain available for DMARC evaluation",
        }

    # ---------------------------------------------------------
    # 6. Unified result
    # ---------------------------------------------------------

    return {
        "from_domain": context.from_domain,
        "envelope_from": context.envelope_from,
        "envelope_from_domain": context.envelope_from_domain,
        "sender_ip": context.sender_ip,
        "helo": context.helo,

        "spf": spf_result,

        "dkim": dkim_result,
        "dkim_signatures": dkim_results,

        "dmarc": dmarc_result,
    }