import ipaddress

import dns
import dns.exception
import dns.resolver

from .dns_utils import (
    resolve_txt_records,
    resolve_mx_records,
    resolve_ip_addresses,
)


# =============================================================
# SPF CONSTANTS
# =============================================================

QUALIFIER_STATUS = {
    "+": "PASS",
    "-": "FAIL",
    "~": "SOFTFAIL",
    "?": "NEUTRAL",
}

MAX_DNS_LOOKUPS = 10


# =============================================================
# SPF RECORD LOOKUP
# =============================================================

def get_spf_record(domain: str):
    """
    Retrieve the SPF record for a domain.

    Returns:
        str | None:
            SPF record if found.
            None if the domain has no SPF record.

    Raises:
        RuntimeError:
            If a DNS failure prevents the SPF record from
            being retrieved.
    """

    try:
        txt_records = resolve_txt_records(domain)

    except dns.resolver.NXDOMAIN:
        return None

    except dns.resolver.NoAnswer:
        return None

    except (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ) as exc:
        raise RuntimeError(
            f"DNS error while retrieving SPF record "
            f"for {domain}: {exc}"
        ) from exc

    for record in txt_records:

        if record.lower().startswith("v=spf1"):
            return record

    return None


# =============================================================
# IP MECHANISM CHECK
# =============================================================

def check_ip_mechanism(sender_ip: str, mechanism: str):
    """
    Check whether sender_ip matches an SPF ip4 or ip6 mechanism.

    Examples:

        sender_ip = "192.0.2.10"
        mechanism = "ip4:192.0.2.0/24"

        sender_ip = "2001:db8::10"
        mechanism = "ip6:2001:db8::/64"
    """

    if not sender_ip:
        return False

    try:
        sender = ipaddress.ip_address(sender_ip)

        if ":" not in mechanism:
            return False

        mechanism_type, network_value = mechanism.split(
            ":",
            1,
        )

        if mechanism_type not in {"ip4", "ip6"}:
            return False

        network = ipaddress.ip_network(
            network_value,
            strict=False,
        )

        # Prevent IPv4 addresses from being compared against
        # IPv6 networks and vice versa.
        if sender.version != network.version:
            return False

        return sender in network

    except (
        ValueError,
        IndexError,
    ):
        return False


# =============================================================
# SPF EVALUATION
# =============================================================

def evaluate_spf_record(
    domain: str,
    sender_ip: str,
    record: str,
    visited_domains=None,
    lookup_count=None,
    record_lookup=None,
):
    """
    Evaluate an SPF record.

    Currently supports:

        - ip4
        - ip6
        - include
        - mx
        - all

    Protection:

        - recursive include detection
        - DNS lookup limit
        - DNS error propagation
        - IPv4/IPv6 MX support
    """

    if visited_domains is None:
        visited_domains = set()

    if lookup_count is None:
        lookup_count = [0]

    if record_lookup is None:
        record_lookup = get_spf_record

    # ---------------------------------------------------------
    # Recursive include protection
    # ---------------------------------------------------------

    domain = domain.lower().rstrip(".")

    if domain in visited_domains:
        return {
            "status": "PERMERROR",
            "mechanism": None,
            "reason": (
                f"Recursive SPF include detected "
                f"for {domain}"
            ),
        }

    visited_domains.add(domain)

    # ---------------------------------------------------------
    # Parse mechanisms
    # ---------------------------------------------------------

    parts = record.split()

    if not parts or parts[0].lower() != "v=spf1":
        return {
            "status": "PERMERROR",
            "mechanism": None,
            "reason": "Invalid SPF record",
        }

    mechanisms = parts[1:]

    # ---------------------------------------------------------
    # Evaluate mechanisms
    # ---------------------------------------------------------

    for mechanism in mechanisms:

        if not mechanism:
            continue

        # -----------------------------------------------------
        # Qualifier
        # -----------------------------------------------------

        qualifier = "+"

        if mechanism[0] in "+-~?":
            qualifier = mechanism[0]
            mechanism = mechanism[1:]

        mechanism_lower = mechanism.lower()

        # -----------------------------------------------------
        # ip4 / ip6
        # -----------------------------------------------------

        if mechanism_lower.startswith(("ip4:", "ip6:")):

            if check_ip_mechanism(
                sender_ip,
                mechanism_lower,
            ):
                return {
                    "status": QUALIFIER_STATUS[qualifier],
                    "mechanism": mechanism_lower,
                    "reason": (
                        f"Sender IP {sender_ip} matched "
                        f"{mechanism_lower}"
                    ),
                }

            continue

        # -----------------------------------------------------
        # include
        # -----------------------------------------------------

        elif mechanism_lower.startswith("include:"):

            included_domain = mechanism.split(
                ":",
                1,
            )[1].lower().rstrip(".")

            # One DNS lookup for the include.
            lookup_count[0] += 1

            if lookup_count[0] > MAX_DNS_LOOKUPS:
                return {
                    "status": "PERMERROR",
                    "mechanism": mechanism_lower,
                    "reason": (
                        "Maximum SPF DNS lookup "
                        "limit exceeded"
                    ),
                }

            if included_domain in visited_domains:
                return {
                    "status": "PERMERROR",
                    "mechanism": mechanism_lower,
                    "reason": (
                        f"Recursive SPF include detected "
                        f"for {included_domain}"
                    ),
                }

            try:
                included_record = record_lookup(
                    included_domain
                )

            except RuntimeError as exc:
                return {
                    "status": "TEMPERROR",
                    "mechanism": mechanism_lower,
                    "reason": (
                        f"DNS error while retrieving "
                        f"included SPF record "
                        f"for {included_domain}: {exc}"
                    ),
                }

            if included_record is None:
                # include did not match.
                continue

            included_result = evaluate_spf_record(
                domain=included_domain,
                sender_ip=sender_ip,
                record=included_record,
                visited_domains=visited_domains.copy(),
                lookup_count=lookup_count,
                record_lookup=record_lookup,
            )

            # -------------------------------------------------
            # INCLUDE semantics
            # -------------------------------------------------

            if included_result["status"] == "PASS":
                return {
                    "status": QUALIFIER_STATUS[qualifier],
                    "mechanism": mechanism_lower,
                    "reason": (
                        f"Sender IP matched SPF policy "
                        f"included from "
                        f"{included_domain}"
                    ),
                }

            # Errors propagate.
            if included_result["status"] in {
                "PERMERROR",
                "TEMPERROR",
            }:
                return {
                    "status": included_result["status"],
                    "mechanism": mechanism_lower,
                    "reason": (
                        f"SPF evaluation error while "
                        f"processing included domain "
                        f"{included_domain}: "
                        f"{included_result['reason']}"
                    ),
                }

            # FAIL, SOFTFAIL, NEUTRAL, NONE:
            # include did not match.
            continue

        # -----------------------------------------------------
        # mx
        # -----------------------------------------------------

        elif mechanism_lower == "mx":

            # DNS lookup for MX.
            lookup_count[0] += 1

            if lookup_count[0] > MAX_DNS_LOOKUPS:
                return {
                    "status": "PERMERROR",
                    "mechanism": "mx",
                    "reason": (
                        "Maximum SPF DNS lookup "
                        "limit exceeded"
                    ),
                }

            try:
                mx_records = resolve_mx_records(domain)

            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
            ):
                continue

            except (
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ) as exc:
                return {
                    "status": "TEMPERROR",
                    "mechanism": "mx",
                    "reason": (
                        f"DNS error while resolving "
                        f"MX records for {domain}: {exc}"
                    ),
                }

            # -------------------------------------------------
            # Check each MX host
            # -------------------------------------------------

            for mx_host in mx_records:

                # Resolving A/AAAA for each MX host consumes
                # DNS lookup budget.
                lookup_count[0] += 1

                if lookup_count[0] > MAX_DNS_LOOKUPS:
                    return {
                        "status": "PERMERROR",
                        "mechanism": "mx",
                        "reason": (
                            "Maximum SPF DNS lookup "
                            "limit exceeded"
                        ),
                    }

                try:
                    mx_ips = resolve_ip_addresses(
                        mx_host
                    )

                except (
                    dns.resolver.NXDOMAIN,
                    dns.resolver.NoAnswer,
                ):
                    continue

                except (
                    dns.resolver.NoNameservers,
                    dns.exception.Timeout,
                ) as exc:
                    return {
                        "status": "TEMPERROR",
                        "mechanism": "mx",
                        "reason": (
                            f"DNS error while resolving "
                            f"{mx_host}: {exc}"
                        ),
                    }

                # -------------------------------------------------
                # Compare sender IP against MX addresses
                # -------------------------------------------------

                for mx_ip in mx_ips:

                    try:
                        parsed_ip = ipaddress.ip_address(
                            mx_ip
                        )

                    except ValueError:
                        continue

                    if parsed_ip.version == 4:
                        ip_mechanism = f"ip4:{mx_ip}"

                    else:
                        ip_mechanism = f"ip6:{mx_ip}"

                    if check_ip_mechanism(
                        sender_ip,
                        ip_mechanism,
                    ):
                        return {
                            "status": QUALIFIER_STATUS[
                                qualifier
                            ],
                            "mechanism": "mx",
                            "reason": (
                                f"Sender IP "
                                f"{sender_ip} matched "
                                f"MX host {mx_host} "
                                f"({mx_ip})"
                            ),
                        }

            continue

        # -----------------------------------------------------
        # all
        # -----------------------------------------------------

        elif mechanism_lower == "all":

            actual_mechanism = f"{qualifier}all"

            if qualifier == "-":
                reason = (
                    "Sender IP did not match any "
                    "authorized SPF mechanism"
                )

            elif qualifier == "~":
                reason = (
                    "Sender IP did not match "
                    "authorized SPF mechanisms"
                )

            elif qualifier == "?":
                reason = (
                    "Domain makes no assertion "
                    "about the sender IP"
                )

            else:
                reason = (
                    "All senders are authorized "
                    "by the SPF policy"
                )

            return {
                "status": QUALIFIER_STATUS[qualifier],
                "mechanism": actual_mechanism,
                "reason": reason,
            }

        # -----------------------------------------------------
        # Unsupported mechanism
        # -----------------------------------------------------

        else:
            # This version intentionally ignores unsupported
            # mechanisms instead of incorrectly treating them
            # as a match.
            continue

    # ---------------------------------------------------------
    # No supported mechanism matched
    # ---------------------------------------------------------

    return {
        "status": "NEUTRAL",
        "mechanism": None,
        "reason": (
            "No supported SPF mechanism matched"
        ),
    }


# =============================================================
# PUBLIC SPF CHECK
# =============================================================

def check_spf(
    domain: str,
    sender_ip: str,
):
    """
    Perform an SPF check for a domain and sender IP.

    Returns a structured result.

    If sender_ip is unavailable, SPF cannot be independently
    evaluated. The result is returned as NONE with an explicit
    explanation rather than inventing a sender IP.
    """

    domain = (
        domain.strip()
        .lower()
        .rstrip(".")
        if domain
        else domain
    )

    # ---------------------------------------------------------
    # Sender IP unavailable
    # ---------------------------------------------------------

    if not sender_ip:
        return {
            "domain": domain,
            "sender_ip": None,
            "record": None,
            "status": "NONE",
            "mechanism": None,
            "reason": (
                "Sender IP is unavailable; "
                "SPF cannot be independently evaluated"
            ),
        }

    # ---------------------------------------------------------
    # Validate sender IP
    # ---------------------------------------------------------

    try:
        ipaddress.ip_address(sender_ip)

    except ValueError:
        return {
            "domain": domain,
            "sender_ip": sender_ip,
            "record": None,
            "status": "PERMERROR",
            "mechanism": None,
            "reason": (
                f"Invalid sender IP address: "
                f"{sender_ip}"
            ),
        }

    # ---------------------------------------------------------
    # Retrieve SPF record
    # ---------------------------------------------------------

    try:
        record = get_spf_record(domain)

    except RuntimeError as exc:
        return {
            "domain": domain,
            "sender_ip": sender_ip,
            "record": None,
            "status": "TEMPERROR",
            "mechanism": None,
            "reason": str(exc),
        }

    # ---------------------------------------------------------
    # No SPF record
    # ---------------------------------------------------------

    if record is None:
        return {
            "domain": domain,
            "sender_ip": sender_ip,
            "record": None,
            "status": "NONE",
            "mechanism": None,
            "reason": "No SPF record found",
        }

    # ---------------------------------------------------------
    # Evaluate SPF record
    # ---------------------------------------------------------

    result = evaluate_spf_record(
        domain=domain,
        sender_ip=sender_ip,
        record=record,
    )

    # ---------------------------------------------------------
    # Final structured result
    # ---------------------------------------------------------

    return {
        "domain": domain,
        "sender_ip": sender_ip,
        "record": record,
        **result,
    }