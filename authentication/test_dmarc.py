from authentication.dmarc import (
    apply_dmarc_policy,
    check_dmarc,
    get_dmarc_record,
    parse_dmarc_record,
    check_domain_alignment,
    evaluate_dmarc_alignment,
)

print("=" * 60)
print("DMARC DNS LOOKUP TEST")
print("=" * 60)


# ============================================================
# Test 1: Domain with DMARC record
# ============================================================

domain = "google.com"

print(f"Domain: {domain}")
print("DMARC record:")

try:
    record = get_dmarc_record(domain)
    print(record)

except Exception as exc:
    print("ERROR:", exc)


print("=" * 60)


# ============================================================
# Test 2: Domain without DMARC record
# ============================================================

domain = "example.invalid"

print(f"Domain: {domain}")
print("DMARC record:")

try:
    record = get_dmarc_record(domain)
    print(record)

except Exception as exc:
    print("ERROR:", exc)


print("=" * 60)

from authentication.dmarc import (
    get_dmarc_record,
    parse_dmarc_record,
)



domain = "google.com"

print(f"Domain: {domain}")
print("DMARC record:")

try:
    record = get_dmarc_record(domain)
    print(record)

except Exception as exc:
    print("ERROR:", exc)


print("=" * 60)

domain = "example.invalid"

print(f"Domain: {domain}")
print("DMARC record:")

try:
    record = get_dmarc_record(domain)
    print(record)

except Exception as exc:
    print("ERROR:", exc)


print("=" * 60)
print("DMARC RECORD PARSING TEST")
print("=" * 60)

record = (
    "v=DMARC1; "
    "p=quarantine; "
    "sp=reject; "
    "adkim=s; "
    "aspf=r; "
    "pct=50; "
    "rua=mailto:dmarc@example.com"
)

result = parse_dmarc_record(record)

print(result)


print("=" * 60)
print("DMARC MINIMAL RECORD TEST")
print("=" * 60)

record = "v=DMARC1; p=none"

result = parse_dmarc_record(record)

print(result)


print("=" * 60)
print("DMARC MISSING POLICY TEST")
print("=" * 60)

record = "v=DMARC1; rua=mailto:dmarc@example.com"

result = parse_dmarc_record(record)

print(result)


print("=" * 60)
print("DMARC INVALID VERSION TEST")
print("=" * 60)

record = "v=DMARC2; p=reject"

result = parse_dmarc_record(record)

print(result)


print("=" * 60)
print("DMARC DUPLICATE TAG TEST")
print("=" * 60)

record = "v=DMARC1; p=reject; p=none"

result = parse_dmarc_record(record)

print(result)


from authentication.dmarc import (
    check_domain_alignment,
)


print("=" * 60)
print("DMARC STRICT ALIGNMENT TEST")
print("=" * 60)

print(
    check_domain_alignment(
        from_domain="example.com",
        authenticated_domain="example.com",
        mode="s",
    )
)

print(
    check_domain_alignment(
        from_domain="example.com",
        authenticated_domain="mail.example.com",
        mode="s",
    )
)


print("=" * 60)
print("DMARC RELAXED ALIGNMENT TEST")
print("=" * 60)

print(
    check_domain_alignment(
        from_domain="example.com",
        authenticated_domain="mail.example.com",
        mode="r",
    )
)

print(
    check_domain_alignment(
        from_domain="example.com",
        authenticated_domain="attacker.com",
        mode="r",
    )
)


print("=" * 60)
print("DMARC SPF/DKIM ALIGNMENT DECISION TEST")
print("=" * 60)

print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="PASS",
        spf_domain="example.com",
        dkim_status="FAIL",
        dkim_domain="example.com",
        aspf="r",
        adkim="r",
    )
)

print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="FAIL",
        spf_domain="example.com",
        dkim_status="PASS",
        dkim_domain="example.com",
        aspf="r",
        adkim="r",
    )
)

print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="FAIL",
        spf_domain="attacker.com",
        dkim_status="FAIL",
        dkim_domain="attacker.com",
        aspf="r",
        adkim="r",
    )
)

print("=" * 60)
print("DMARC ALIGNMENT EDGE CASE TEST")
print("=" * 60)

print("SPF PASS but NOT aligned:")
print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="PASS",
        spf_domain="attacker.com",
        dkim_status="FAIL",
        dkim_domain=None,
        aspf="r",
        adkim="r",
    )
)

print("DKIM PASS but NOT aligned:")
print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="FAIL",
        spf_domain=None,
        dkim_status="PASS",
        dkim_domain="attacker.com",
        aspf="r",
        adkim="r",
    )
)

print("SPF aligned + DKIM unaligned:")
print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="PASS",
        spf_domain="example.com",
        dkim_status="PASS",
        dkim_domain="attacker.com",
        aspf="r",
        adkim="r",
    )
)

print("SPF unaligned + DKIM aligned:")
print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="PASS",
        spf_domain="attacker.com",
        dkim_status="PASS",
        dkim_domain="example.com",
        aspf="r",
        adkim="r",
    )
)

print("Strict alignment:")
print(
    evaluate_dmarc_alignment(
        from_domain="example.com",
        spf_status="PASS",
        spf_domain="mail.example.com",
        dkim_status="FAIL",
        dkim_domain=None,
        aspf="s",
        adkim="s",
    )
)

print("=" * 60)
print("DMARC POLICY APPLICATION TEST")
print("=" * 60)

print("PASS + none:")
print(
    apply_dmarc_policy(
        dmarc_status="PASS",
        policy="none"
    )
)

print("PASS + quarantine:")
print(
    apply_dmarc_policy(
        dmarc_status="PASS",
        policy="quarantine"
    )
)

print("FAIL + none:")
print(
    apply_dmarc_policy(
        dmarc_status="FAIL",
        policy="none"
    )
)

print("FAIL + quarantine:")
print(
    apply_dmarc_policy(
        dmarc_status="FAIL",
        policy="quarantine"
    )
)

print("FAIL + reject:")
print(
    apply_dmarc_policy(
        dmarc_status="FAIL",
        policy="reject"
    )
)

print("Invalid policy:")
print(
    apply_dmarc_policy(
        dmarc_status="FAIL",
        policy="invalid"
    )
)

print("=" * 60)
print("COMPLETE DMARC VERIFICATION TEST")
print("=" * 60)

spf_result = {
    "status": "PASS",
    "domain": "example.com"
}

dkim_result = {
    "status": "PASS",
    "domain": "example.com"
}

print(
    check_dmarc(
        from_domain="example.com",
        spf_result=spf_result,
        dkim_result=dkim_result
    )
)

print("=" * 60)
print("COMPLETE DMARC FAILURE POLICY TEST")
print("=" * 60)


def run_dmarc_test(name, from_domain, spf_result, dkim_result):
    print(name)
    print(
        check_dmarc(
            from_domain=from_domain,
            spf_result=spf_result,
            dkim_result=dkim_result
        )
    )
    print("-" * 60)


# ---------------------------------------------------------
# DMARC FAIL + p=none
# ---------------------------------------------------------

run_dmarc_test(
    "FAIL + p=none",
    "example.com",

    {
        "status": "PASS",
        "domain": "attacker.com"
    },

    {
        "status": "FAIL",
        "domain": "attacker.com"
    }
)


# ---------------------------------------------------------
# DMARC FAIL + p=quarantine
# ---------------------------------------------------------

run_dmarc_test(
    "FAIL + p=quarantine",
    "google.com",

    {
        "status": "PASS",
        "domain": "attacker.com"
    },

    {
        "status": "FAIL",
        "domain": "attacker.com"
    }
)


# ---------------------------------------------------------
# DMARC FAIL + p=reject
# ---------------------------------------------------------

run_dmarc_test(
    "FAIL + p=reject",
    "example.com",

    {
        "status": "PASS",
        "domain": "attacker.com"
    },

    {
        "status": "FAIL",
        "domain": "attacker.com"
    }
)


# ---------------------------------------------------------
# SPF aligned, DKIM unaligned
# ---------------------------------------------------------

run_dmarc_test(
    "SPF aligned + DKIM unaligned",
    "example.com",

    {
        "status": "PASS",
        "domain": "example.com"
    },

    {
        "status": "PASS",
        "domain": "attacker.com"
    }
)


# ---------------------------------------------------------
# SPF unaligned, DKIM aligned
# ---------------------------------------------------------

run_dmarc_test(
    "SPF unaligned + DKIM aligned",
    "example.com",

    {
        "status": "PASS",
        "domain": "attacker.com"
    },

    {
        "status": "PASS",
        "domain": "example.com"
    }
)
