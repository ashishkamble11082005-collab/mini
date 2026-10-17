from authentication.spf import check_spf, evaluate_spf_record
from authentication.dns_utils import resolve_mx_records, resolve_ip_addresses

# ============================================================
# Controlled SPF evaluation tests
# These tests do not depend on live DNS.
# ============================================================

def run_logic_tests():

    tests = [
        {
            "name": "IPv4 match",
            "domain": "test.local",
            "sender_ip": "192.0.2.10",
            "record": "v=spf1 ip4:192.0.2.0/24 -all"
        },
        {
            "name": "IPv4 no match",
            "domain": "test.local",
            "sender_ip": "198.51.100.10",
            "record": "v=spf1 ip4:192.0.2.0/24 -all"
        },
        {
            "name": "IPv6 match",
            "domain": "test.local",
            "sender_ip": "2001:db8:1234::10",
            "record": "v=spf1 ip6:2001:db8:1234::/48 -all"
        },
        {
            "name": "IPv6 no match",
            "domain": "test.local",
            "sender_ip": "2001:db8:5678::10",
            "record": "v=spf1 ip6:2001:db8:1234::/48 -all"
        },
        {
            "name": "Hard fail",
            "domain": "test.local",
            "sender_ip": "198.51.100.10",
            "record": "v=spf1 -all"
        },
        {
            "name": "Soft fail",
            "domain": "test.local",
            "sender_ip": "198.51.100.10",
            "record": "v=spf1 ~all"
        },
        {
            "name": "Neutral",
            "domain": "test.local",
            "sender_ip": "198.51.100.10",
            "record": "v=spf1 ?all"
        },
        {
            "name": "Pass all",
            "domain": "test.local",
            "sender_ip": "198.51.100.10",
            "record": "v=spf1 +all"
        }
    ]

    print("\n" + "=" * 60)
    print("SPF CORE LOGIC TESTS")
    print("=" * 60)

    for test in tests:

        result = evaluate_spf_record(
            domain=test["domain"],
            sender_ip=test["sender_ip"],
            record=test["record"]
        )

        print(f"\n{test['name']}")
        print("Sender IP:", test["sender_ip"])
        print("SPF:", test["record"])
        print("Result:", result)

# ============================================================
# MX DNS tests
# ============================================================

def run_mx_tests():

    domain = "google.com"

    print("\n" + "=" * 60)
    print("MX DNS TEST")
    print("=" * 60)

    mx_records = resolve_mx_records(domain)

    print("Domain:", domain)
    print("MX Records:", mx_records)

    for mx_host in mx_records:

        ips = resolve_ip_addresses(mx_host)

        print("\nMail Server:", mx_host)
        print("IPv4 Addresses:", ips)
# ============================================================
# Controlled INCLUDE tests
# ============================================================

def run_include_tests():

    fake_records = {

        "_spf.test":
            "v=spf1 ip4:192.0.2.10 -all",

        "_spf.fail":
            "v=spf1 ip4:203.0.113.10 -all",

        "_spf.level1":
            "v=spf1 include:_spf.level2 -all",

        "_spf.level2":
            "v=spf1 ip4:192.0.2.10 -all",

        "_spf.circular1":
            "v=spf1 include:_spf.circular2 -all",

        "_spf.circular2":
            "v=spf1 include:_spf.circular1 -all"
    }

    def fake_record_lookup(domain):

        print(f"DNS lookup: {domain}")

        return fake_records.get(domain)

    tests = [

        {
            "name": "Include PASS",
            "sender_ip": "192.0.2.10",
            "record": "v=spf1 include:_spf.test -all"
        },

        {
            "name": "Include FAIL then parent -all",
            "sender_ip": "192.0.2.10",
            "record": "v=spf1 include:_spf.fail -all"
        },

        {
            "name": "Nested include",
            "sender_ip": "192.0.2.10",
            "record": "v=spf1 include:_spf.level1 -all"
        },

        {
            "name": "Circular include",
            "sender_ip": "192.0.2.10",
            "record": "v=spf1 include:_spf.circular1 -all"
        }
    ]

    print("\n" + "=" * 60)
    print("SPF INCLUDE TESTS")
    print("=" * 60)

    for test in tests:

        print(f"\n{test['name']}")

        result = evaluate_spf_record(
            domain="test.local",
            sender_ip=test["sender_ip"],
            record=test["record"],
            record_lookup=fake_record_lookup
        )

        print("Result:", result)


# ============================================================
# Real DNS integration test
# ============================================================

def run_dns_test():

    domain = "domain.com"

    sender_ip = "fdcf:abda:4154::1234"

    print("\n" + "=" * 60)
    print("SPF REAL DNS TEST")
    print("=" * 60)

    result = check_spf(
        domain,
        sender_ip
    )

    print("Domain:", domain)
    print("Sender IP:", sender_ip)
    print("Result:", result)


# ============================================================
# Run all tests
# ============================================================

if __name__ == "__main__":

    run_logic_tests()

    run_include_tests()

    run_mx_tests()

    run_dns_test()