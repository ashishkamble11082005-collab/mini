import dns.resolver
import dns.exception


def resolve_txt_records(domain: str):
    """
    Resolve TXT records for a domain.

    DNS exceptions are intentionally allowed to propagate so that
    callers can distinguish between:
        - no record
        - DNS failure
        - timeout
    """

    answers = dns.resolver.resolve(domain, "TXT")

    records = []

    for answer in answers:
        record = "".join(
            part.decode("utf-8")
            if isinstance(part, bytes)
            else part
            for part in answer.strings
        )

        records.append(record)

    return records


def resolve_mx_records(domain: str):
    """
    Resolve MX records.

    DNS exceptions are intentionally NOT swallowed.
    SPF needs to distinguish DNS failure from an empty result.
    """

    answers = dns.resolver.resolve(domain, "MX")

    records = []

    for answer in answers:
        records.append(
            str(answer.exchange).rstrip(".")
        )

    return records


def resolve_ip_addresses(hostname: str):
    """
    Resolve both IPv4 and IPv6 addresses.

    Returns:
        list[str]

    Supports:
        A
        AAAA

    DNS exceptions are propagated so SPF can correctly
    classify DNS failures as TEMPERROR.
    """

    addresses = []

    # ---------------------------------------------------------
    # IPv4
    # ---------------------------------------------------------

    try:
        answers = dns.resolver.resolve(hostname, "A")

        for answer in answers:
            addresses.append(str(answer))

    except dns.resolver.NoAnswer:
        pass

    # ---------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------

    try:
        answers = dns.resolver.resolve(hostname, "AAAA")

        for answer in answers:
            addresses.append(str(answer))

    except dns.resolver.NoAnswer:
        pass

    # ---------------------------------------------------------
    # No address records
    # ---------------------------------------------------------

    if not addresses:
        raise dns.resolver.NoAnswer(
            response=None
        )

    return addresses


def resolve_dkim_key(domain: str, selector: str):
    """
    Resolve the DKIM public-key TXT record.
    """

    dkim_domain = f"{selector}._domainkey.{domain}"

    txt_records = resolve_txt_records(dkim_domain)

    for record in txt_records:
        if record.lower().startswith("v=dkim1"):
            return record

    return None