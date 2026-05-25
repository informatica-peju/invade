#!/usr/bin/env python3
"""Query one domain across multiple public DNS resolvers using DoH JSON APIs."""

import argparse
import json
import urllib.parse
import urllib.request


RESOLVERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "opendns": "https://doh.opendns.com/dns-query",
    "adguard": "https://dns.adguard-dns.com/dns-query",
}

QTYPE_MAP = {
    "A": 1,
    "CNAME": 5,
    "AAAA": 28,
}


def query_resolver(base_url: str, domain: str, qtype: str):
    params = urllib.parse.urlencode({"name": domain, "type": qtype})
    url = f"{base_url}?{params}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "user-agent": "invade-dns-toolkit/1.0"})
    with urllib.request.urlopen(req, timeout=12) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))

    answers = []
    for ans in payload.get("Answer", []) or []:
        if ans.get("type") == QTYPE_MAP[qtype]:
            answers.append(ans.get("data"))

    return {
        "status": payload.get("Status"),
        "ad": payload.get("AD"),
        "cd": payload.get("CD"),
        "answers": answers,
        "raw_answer_count": len(payload.get("Answer", []) or []),
    }


def main():
    parser = argparse.ArgumentParser(description="Check one domain across multiple DoH resolvers")
    parser.add_argument("domain", help="Domain to resolve, e.g. taiwebs.com")
    parser.add_argument("--types", default="A,AAAA,CNAME", help="Comma-separated record types (default: A,AAAA,CNAME)")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    types = [t.strip().upper() for t in args.types.split(",") if t.strip()]

    print(f"domain={domain}")
    print(f"types={','.join(types)}")

    for name, base_url in RESOLVERS.items():
        print(f"\n[{name}] {base_url}")
        for qtype in types:
            try:
                result = query_resolver(base_url, domain, qtype)
                answers = result["answers"]
                if answers:
                    print(f"  {qtype}: {', '.join(answers)}")
                else:
                    print(f"  {qtype}: (no direct answer) status={result['status']} answer_count={result['raw_answer_count']}")
            except Exception as exc:
                print(f"  {qtype}: ERROR {exc}")


if __name__ == "__main__":
    main()
