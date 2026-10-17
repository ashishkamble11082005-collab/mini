import authentication.dmarc as dmarc
from authentication.dmarc import check_dmarc


# =========================================================
# CONTROLLED DMARC TEST
# =========================================================

def run_test(name, dmarc_record, spf_result, dkim_result):

    print("=" * 60)
    print(name)
    print("=" * 60)

    # -----------------------------------------------------
    # We temporarily replace the DNS lookup function
    # with a controlled test record.
    # -----------------------------------------------------



    original_get_dmarc_record = dmarc.get_dmarc_record

    dmarc.get_dmarc_record = lambda domain: dmarc_record

    try:

        result = check_dmarc(
            from_domain="example.com",
            spf_result=spf_result,
            dkim_result=dkim_result
        )

        print(result)

    finally:

        # Restore the original DNS function
        dmarc.get_dmarc_record = original_get_dmarc_record


# =========================================================
# COMMON RESULTS
# =========================================================

PASS_SPF = {
    "status": "PASS",
    "domain": "example.com"
}

PASS_DKIM = {
    "status": "PASS",
    "domain": "example.com"
}

FAIL_SPF = {
    "status": "FAIL",
    "domain": "attacker.com"
}

FAIL_DKIM = {
    "status": "FAIL",
    "domain": "attacker.com"
}


# =========================================================
# 1. DMARC PASS + p=none
# =========================================================

run_test(
    "DMARC PASS + p=none",

    "v=DMARC1; p=none",

    PASS_SPF,
    PASS_DKIM
)


# =========================================================
# 2. DMARC PASS + p=quarantine
# =========================================================

run_test(
    "DMARC PASS + p=quarantine",

    "v=DMARC1; p=quarantine",

    PASS_SPF,
    PASS_DKIM
)


# =========================================================
# 3. DMARC PASS + p=reject
# =========================================================

run_test(
    "DMARC PASS + p=reject",

    "v=DMARC1; p=reject",

    PASS_SPF,
    PASS_DKIM
)


# =========================================================
# 4. DMARC FAIL + p=none
# =========================================================

run_test(
    "DMARC FAIL + p=none",

    "v=DMARC1; p=none",

    FAIL_SPF,
    FAIL_DKIM
)


# =========================================================
# 5. DMARC FAIL + p=quarantine
# =========================================================

run_test(
    "DMARC FAIL + p=quarantine",

    "v=DMARC1; p=quarantine",

    FAIL_SPF,
    FAIL_DKIM
)


# =========================================================
# 6. DMARC FAIL + p=reject
# =========================================================

run_test(
    "DMARC FAIL + p=reject",

    "v=DMARC1; p=reject",

    FAIL_SPF,
    FAIL_DKIM
)
