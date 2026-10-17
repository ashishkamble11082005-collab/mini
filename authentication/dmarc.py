import dns

from .dns_utils import resolve_txt_records


def get_dmarc_record(domain: str):
    """
    Retrieve the DMARC record for a domain.

    DMARC records are published as TXT records at:

        _dmarc.<domain>

    Returns:
        str | None:
            DMARC record if found, otherwise None.

    Raises:
        RuntimeError:
            When a DNS problem prevents the lookup.
    """

    dmarc_domain = f"_dmarc.{domain}"

    try:
        txt_records = resolve_txt_records(
            dmarc_domain
        )

    except dns.resolver.NXDOMAIN:
        return None

    except dns.resolver.NoAnswer:
        return None

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ) as exc:
        raise RuntimeError(
            f"DNS error while retrieving DMARC record "
            f"for {domain}: {exc}"
        ) from exc

    for record in txt_records:

        if record.lower().startswith("v=dmarc1"):
            return record

    return None

def parse_dmarc_record(record: str):
    """
    Parse and validate a DMARC record.

    Returns:
        dict: Parsed DMARC parameters.
    """

    if not record:
        return {
            "valid": False,
            "reason": "DMARC record is missing"
        }

    tags = {}

    for part in record.split(";"):

        part = part.strip()

        if not part:
            continue

        if "=" not in part:
            return {
                "valid": False,
                "reason": f"Malformed DMARC tag: {part}"
            }

        key, value = part.split("=", 1)

        key = key.strip().lower()
        value = value.strip()

        if not key:
            return {
                "valid": False,
                "reason": "DMARC tag name is empty"
            }

        if key in tags:
            return {
                "valid": False,
                "reason": f"Duplicate DMARC tag: {key}",
                "tags": tags
            }

        tags[key] = value

    if tags.get("v") != "DMARC1":
        return {
            "valid": False,
            "reason": "Invalid or missing DMARC version",
            "tags": tags
        }

    if "p" not in tags:
        return {
            "valid": False,
            "reason": "Missing required DMARC policy tag: p",
            "tags": tags
        }

    policy = tags["p"].lower()

    if policy not in {
        "none",
        "quarantine",
        "reject",
    }:
        return {
            "valid": False,
            "reason": f"Invalid DMARC policy: {tags['p']}",
            "tags": tags
        }

    subdomain_policy = tags.get(
        "sp",
        policy
    ).lower()

    if subdomain_policy not in {
        "none",
        "quarantine",
        "reject",
    }:
        return {
            "valid": False,
            "reason": (
                f"Invalid DMARC subdomain policy: "
                f"{tags.get('sp')}"
            ),
            "tags": tags
        }

    adkim = tags.get(
        "adkim",
        "r"
    ).lower()

    if adkim not in {"r", "s"}:
        return {
            "valid": False,
            "reason": f"Invalid DKIM alignment mode: {adkim}",
            "tags": tags
        }

    aspf = tags.get(
        "aspf",
        "r"
    ).lower()

    if aspf not in {"r", "s"}:
        return {
            "valid": False,
            "reason": f"Invalid SPF alignment mode: {aspf}",
            "tags": tags
        }

    try:
        pct = int(
            tags.get("pct", "100")
        )

    except ValueError:
        return {
            "valid": False,
            "reason": "DMARC pct tag must be an integer",
            "tags": tags
        }

    if not 0 <= pct <= 100:
        return {
            "valid": False,
            "reason": "DMARC pct must be between 0 and 100",
            "tags": tags
        }

    return {
        "valid": True,
        "version": tags["v"],
        "policy": policy,
        "subdomain_policy": subdomain_policy,
        "adkim": adkim,
        "aspf": aspf,
        "pct": pct,
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "tags": tags
    }


def check_domain_alignment(
    from_domain: str,
    authenticated_domain: str,
    mode: str = "r",
):
    """
    Check DMARC domain alignment.

    Modes:
        r = relaxed
        s = strict

    Returns:
        dict containing alignment result.
    """

    if not from_domain or not authenticated_domain:
        return {
            "aligned": False,
            "mode": mode,
            "reason": "Domain required for alignment check",
        }

    from_domain = from_domain.strip().lower().rstrip(".")
    authenticated_domain = (
        authenticated_domain
        .strip()
        .lower()
        .rstrip(".")
    )

    mode = mode.lower().strip()

    if mode not in {"r", "s"}:
        return {
            "aligned": False,
            "mode": mode,
            "reason": f"Unsupported alignment mode: {mode}",
        }

    # ---------------------------------------------------------
    # Strict alignment
    # ---------------------------------------------------------

    if mode == "s":

        aligned = (
            from_domain == authenticated_domain
        )

        return {
            "aligned": aligned,
            "mode": "s",
            "from_domain": from_domain,
            "authenticated_domain": authenticated_domain,
            "reason": (
                "Domains are strictly aligned"
                if aligned
                else "Domains are not strictly aligned"
            ),
        }

    # ---------------------------------------------------------
    # Relaxed alignment
    # ---------------------------------------------------------

    if (
        from_domain == authenticated_domain
        or authenticated_domain.endswith(
            "." + from_domain
        )
        or from_domain.endswith(
            "." + authenticated_domain
        )
    ):
        return {
            "aligned": True,
            "mode": "r",
            "from_domain": from_domain,
            "authenticated_domain": authenticated_domain,
            "reason": "Domains are relaxed aligned",
        }

    return {
        "aligned": False,
        "mode": "r",
        "from_domain": from_domain,
        "authenticated_domain": authenticated_domain,
        "reason": "Domains are not relaxed aligned",
    }

def evaluate_dmarc_alignment(
    from_domain: str,
    spf_status: str,
    spf_domain: str | None,
    dkim_status: str,
    dkim_domain: str | None,
    aspf: str = "r",
    adkim: str = "r",
):
    """
    Evaluate whether SPF or DKIM provides
    an authenticated and DMARC-aligned result.

    DMARC passes when at least one of:
        - SPF passes and is aligned
        - DKIM passes and is aligned
    """

    spf_aligned = False
    dkim_aligned = False

    spf_alignment_result = None
    dkim_alignment_result = None

    # ---------------------------------------------------------
    # SPF alignment
    # ---------------------------------------------------------

    if (
        spf_status
        and spf_status.upper() == "PASS"
        and spf_domain
    ):
        spf_alignment_result = check_domain_alignment(
            from_domain=from_domain,
            authenticated_domain=spf_domain,
            mode=aspf,
        )

        spf_aligned = spf_alignment_result[
            "aligned"
        ]

    # ---------------------------------------------------------
    # DKIM alignment
    # ---------------------------------------------------------

    if (
        dkim_status
        and dkim_status.upper() == "PASS"
        and dkim_domain
    ):
        dkim_alignment_result = check_domain_alignment(
            from_domain=from_domain,
            authenticated_domain=dkim_domain,
            mode=adkim,
        )

        dkim_aligned = dkim_alignment_result[
            "aligned"
        ]

    # ---------------------------------------------------------
    # Final DMARC authentication decision
    # ---------------------------------------------------------

    dmarc_pass = (
        spf_aligned
        or dkim_aligned
    )

    if dmarc_pass:

        if spf_aligned and dkim_aligned:
            reason = (
                "SPF and DKIM both passed "
                "with DMARC alignment"
            )

        elif spf_aligned:
            reason = (
                "SPF passed with DMARC alignment"
            )

        else:
            reason = (
                "DKIM passed with DMARC alignment"
            )

        return {
            "status": "PASS",
            "spf_status": spf_status,
            "spf_domain": spf_domain,
            "spf_aligned": spf_aligned,
            "dkim_status": dkim_status,
            "dkim_domain": dkim_domain,
            "dkim_aligned": dkim_aligned,
            "reason": reason,
        }

    return {
        "status": "FAIL",
        "spf_status": spf_status,
        "spf_domain": spf_domain,
        "spf_aligned": spf_aligned,
        "dkim_status": dkim_status,
        "dkim_domain": dkim_domain,
        "dkim_aligned": dkim_aligned,
        "reason": (
            "Neither SPF nor DKIM produced "
            "an aligned authentication PASS"
        ),
    }

def apply_dmarc_policy(
    dmarc_status: str,
    policy: str
):
    """
    Apply the DMARC policy after authentication evaluation.

    Supported policies:
        none
        quarantine
        reject
    """

    if not dmarc_status:
        return {
            "status": "ERROR",
            "action": None,
            "reason": "DMARC authentication status is required"
        }

    if not policy:
        return {
            "status": "ERROR",
            "action": None,
            "reason": "DMARC policy is required"
        }

    dmarc_status = dmarc_status.upper()
    policy = policy.lower().strip()

    if policy not in {
        "none",
        "quarantine",
        "reject"
    }:
        return {
            "status": "ERROR",
            "action": None,
            "reason": f"Unsupported DMARC policy: {policy}"
        }

    # ---------------------------------------------------------
    # DMARC PASS
    # ---------------------------------------------------------

    if dmarc_status == "PASS":
        return {
            "status": "PASS",
            "action": "none",
            "policy": policy,
            "reason": (
                "DMARC authentication passed, "
                "so the failure policy is not applied"
            )
        }

    # ---------------------------------------------------------
    # DMARC FAIL
    # ---------------------------------------------------------

    if dmarc_status == "FAIL":

        if policy == "none":
            action = "none"
            reason = (
                "DMARC failed but the domain policy "
                "requests no enforcement"
            )

        elif policy == "quarantine":
            action = "quarantine"
            reason = (
                "DMARC failed and the domain policy "
                "requests quarantine"
            )

        else:
            action = "reject"
            reason = (
                "DMARC failed and the domain policy "
                "requests rejection"
            )

        return {
            "status": "FAIL",
            "action": action,
            "policy": policy,
            "reason": reason
        }

    return {
        "status": "ERROR",
        "action": None,
        "policy": policy,
        "reason": (
            f"Unsupported DMARC authentication status: "
            f"{dmarc_status}"
        )
    }

def check_dmarc(
    from_domain: str,
    spf_result: dict,
    dkim_result: dict
):
    """
    Perform complete DMARC evaluation.

    Flow:
        1. Retrieve DMARC record
        2. Parse DMARC record
        3. Evaluate SPF alignment
        4. Evaluate DKIM alignment
        5. Determine DMARC PASS/FAIL
        6. Apply DMARC policy

    Returns:
        dict: Structured DMARC result.
    """

    # ---------------------------------------------------------
    # STEP 1: Get DMARC record
    # ---------------------------------------------------------

    try:
        record = get_dmarc_record(from_domain)

    except RuntimeError as exc:
        return {
            "status": "TEMPERROR",
            "domain": from_domain,
            "record": None,
            "reason": str(exc)
        }

    # ---------------------------------------------------------
    # No DMARC record
    # ---------------------------------------------------------

    if record is None:
        return {
            "status": "NONE",
            "domain": from_domain,
            "record": None,
            "reason": "No DMARC record found"
        }

    # ---------------------------------------------------------
    # STEP 2: Parse DMARC record
    # ---------------------------------------------------------

    parsed = parse_dmarc_record(record)

    if not parsed.get("valid"):
        return {
            "status": "PERMERROR",
            "domain": from_domain,
            "record": record,
            "reason": parsed.get(
                "reason",
                "Invalid DMARC record"
            )
        }

    # ---------------------------------------------------------
    # Extract DMARC settings
    # ---------------------------------------------------------

    policy = parsed["policy"]
    aspf = parsed["aspf"]
    adkim = parsed["adkim"]

    # ---------------------------------------------------------
    # STEP 3 + 4:
    # Evaluate SPF and DKIM alignment
    # ---------------------------------------------------------

    alignment_result = evaluate_dmarc_alignment(
        from_domain=from_domain,

        spf_status=spf_result.get("status"),
        spf_domain=spf_result.get("domain"),

        dkim_status=dkim_result.get("status"),
        dkim_domain=dkim_result.get("domain"),

        aspf=aspf,
        adkim=adkim
    )

    # ---------------------------------------------------------
    # STEP 5 + 6:
    # Apply DMARC policy
    # ---------------------------------------------------------

    policy_result = apply_dmarc_policy(
        dmarc_status=alignment_result["status"],
        policy=policy
    )

    # ---------------------------------------------------------
    # Final structured result
    # ---------------------------------------------------------

    return {
        "status": alignment_result["status"],
        "domain": from_domain,
        "record": record,

        "policy": policy,
        "action": policy_result.get("action"),

        "aspf": aspf,
        "adkim": adkim,

        "spf": {
            "status": spf_result.get("status"),
            "domain": spf_result.get("domain"),
            "aligned": alignment_result.get(
                "spf_aligned"
            )
        },

        "dkim": {
            "status": dkim_result.get("status"),
            "domain": dkim_result.get("domain"),
            "aligned": alignment_result.get(
                "dkim_aligned"
            )
        },

        "reason": (
            alignment_result["reason"]
            + ". "
            + policy_result["reason"]
        )
    }