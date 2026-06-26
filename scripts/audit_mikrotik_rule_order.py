#!/usr/bin/env python3
"""Audit MikroTik firewall/NAT/mangle rule ordering for security and diagnostics."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def collect_commands() -> list[str]:
    return [
        "/system clock print",
        "/system identity print",
        "/interface list print detail",
        "/interface list member print detail",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
        "/ip firewall nat print detail",
        "/ip firewall nat print stats detail",
        "/ip firewall mangle print detail",
        "/ip firewall raw print detail",
        "/ip firewall service-port print detail",
    ]


def parse_rules(text: str) -> list[dict]:
    rules = []
    current = None
    rule_start = re.compile(r"^\s*(?P<num>\d+)\s*(?P<flags>[A-ZXI D]*)(?P<rest>.*)$")
    kv_re = re.compile(r'([A-Za-z0-9_-]+)=("[^"]*"|\S+)')

    for line in text.splitlines():
        match = rule_start.match(line)
        if match:
            if current:
                rules.append(current)
            rest = (match.group("rest") or "").strip()
            comment = ""
            if rest.startswith(";;;"):
                comment = rest[3:].strip()
            current = {
                "num": int(match.group("num")),
                "flags": (match.group("flags") or "").strip(),
                "comment": comment,
                "raw": [line.rstrip()],
            }
            if not comment:
                for key, value in kv_re.findall(rest):
                    current[key] = value.strip('"')
            continue

        if current and line.strip():
            stripped = line.strip()
            if stripped.startswith(";;;"):
                current["comment"] = stripped[3:].strip()
            current["raw"].append(line.rstrip())
            for key, value in kv_re.findall(stripped):
                current[key] = value.strip('"')

    if current:
        rules.append(current)
    return rules


def is_disabled(rule: dict) -> bool:
    return "X" in rule.get("flags", "")


def find_rules(rules: list[dict], **criteria) -> list[dict]:
    found = []
    for rule in rules:
        ok = True
        for key, expected in criteria.items():
            actual = rule.get(key, "")
            if expected not in actual:
                ok = False
                break
        if ok:
            found.append(rule)
    return found


def first_num(rules: list[dict], **criteria):
    matches = find_rules(rules, **criteria)
    return matches[0]["num"] if matches else None


def add_check(checks: list[dict], name: str, ok: bool, detail: str, severity: str = "warning") -> None:
    checks.append({"name": name, "ok": ok, "severity": "ok" if ok else severity, "detail": detail})


def audit_filter(filter_rules: list[dict]) -> list[dict]:
    checks = []
    sip_input_allow = first_num(filter_rules, comment="invade: allow router SIP TCP")
    sip_input_drop = first_num(filter_rules, comment="invade: drop router SIP TCP")
    legacy_tcp = first_num(filter_rules, comment="ACEITA-SIP-TCP")
    legacy_udp = first_num(filter_rules, comment="ACEITA-SIP-UDP")
    legacy_tcp_rules = find_rules(filter_rules, comment="ACEITA-SIP-TCP")
    legacy_udp_rules = find_rules(filter_rules, comment="ACEITA-SIP-UDP")

    add_check(
        checks,
        "SIP input allow before drop",
        sip_input_allow is not None and sip_input_drop is not None and sip_input_allow < sip_input_drop,
        f"allow={sip_input_allow}, drop={sip_input_drop}",
        "critical",
    )
    add_check(
        checks,
        "Legacy SIP input accepts absent or disabled",
        not (legacy_tcp_rules + legacy_udp_rules)
        or all(is_disabled(rule) for rule in legacy_tcp_rules + legacy_udp_rules),
        f"ACEITA-SIP-TCP={legacy_tcp}, ACEITA-SIP-UDP={legacy_udp}",
        "critical",
    )

    sip_forward_allow = first_num(filter_rules, comment="invade: allow SIP dstnat")
    sip_forward_drop = first_num(filter_rules, comment="invade: drop SIP dstnat")
    wan_not_dstnat = first_num(filter_rules, comment="defconf: drop all from WAN not DSTNATed")
    wan_not_dstnat_log = first_num(filter_rules, comment="invade: log/drop WAN forward not dstnat")
    add_check(
        checks,
        "SIP dstnat allow/drop before generic WAN forward drop",
        None not in (sip_forward_allow, sip_forward_drop, wan_not_dstnat)
        and sip_forward_allow < sip_forward_drop < wan_not_dstnat,
        f"allow={sip_forward_allow}, drop={sip_forward_drop}, generic_drop={wan_not_dstnat}",
        "critical",
    )
    add_check(
        checks,
        "WAN not-dstnat logging before generic WAN not-dstnat drop",
        wan_not_dstnat_log is not None and wan_not_dstnat is not None and wan_not_dstnat_log < wan_not_dstnat,
        f"log_drop={wan_not_dstnat_log}, generic_drop={wan_not_dstnat}",
    )

    input_established = first_num(filter_rules, chain="input", action="accept", **{"connection-state": "established"})
    input_invalid_log = first_num(filter_rules, comment="invade: log/drop invalid input")
    input_invalid = first_num(filter_rules, chain="input", action="drop", **{"connection-state": "invalid"})
    input_final_drop = first_num(filter_rules, comment="defconf: drop all not coming from LAN")
    input_probe = first_num(filter_rules, comment="invade: log/drop WAN TCP probes")
    input_other = first_num(filter_rules, comment="invade: log/drop other WAN input")
    add_check(
        checks,
        "Input established accepted before invalid/new drops",
        input_established is not None and input_invalid_log is not None and input_established < input_invalid_log,
        f"established={input_established}, invalid_log={input_invalid_log}",
        "critical",
    )
    add_check(
        checks,
        "Input invalid logging before generic invalid drop",
        input_invalid_log is not None and input_invalid is not None and input_invalid_log <= input_invalid,
        f"invalid_log={input_invalid_log}, invalid_drop={input_invalid}",
    )
    add_check(
        checks,
        "Input probe/other logs before final WAN input drop",
        None not in (input_probe, input_other, input_final_drop) and input_probe < input_other < input_final_drop,
        f"tcp_probe={input_probe}, other={input_other}, final_drop={input_final_drop}",
    )

    fwd_established = first_num(filter_rules, chain="forward", action="accept", **{"connection-state": "established"})
    fwd_invalid_log = first_num(filter_rules, comment="invade: log/drop invalid forward")
    fwd_invalid = first_num(filter_rules, chain="forward", action="drop", **{"connection-state": "invalid"})
    add_check(
        checks,
        "Forward established accepted before invalid/new drops",
        fwd_established is not None and fwd_invalid_log is not None and fwd_established < fwd_invalid_log,
        f"established={fwd_established}, invalid_log={fwd_invalid_log}",
        "critical",
    )
    add_check(
        checks,
        "Forward invalid logging before generic invalid drop",
        fwd_invalid_log is not None and fwd_invalid is not None and fwd_invalid_log <= fwd_invalid,
        f"invalid_log={fwd_invalid_log}, invalid_drop={fwd_invalid}",
    )
    return checks


def audit_nat(nat_rules: list[dict]) -> list[dict]:
    checks = []
    first_srcnat = first_num(nat_rules, chain="srcnat")
    dstnat_5060 = [rule for rule in nat_rules if rule.get("chain") == "dstnat" and "5060" in rule.get("dst-port", "")]
    hairpin = first_num(nat_rules, comment="hairpin-esus")
    netmap_default = first_num(nat_rules, comment="masquerade-by-default")
    esus_dstnat = first_num(nat_rules, comment="esus")

    add_check(
        checks,
        "DSTNAT rules before first SRCNAT",
        bool(dstnat_5060) and first_srcnat is not None and all(rule["num"] < first_srcnat for rule in dstnat_5060),
        f"dstnat_5060={[rule['num'] for rule in dstnat_5060]}, first_srcnat={first_srcnat}",
        "critical",
    )
    add_check(
        checks,
        "eSUS dstnat before hairpin/srcnat",
        esus_dstnat is not None and hairpin is not None and esus_dstnat < hairpin,
        f"esus_dstnat={esus_dstnat}, hairpin={hairpin}",
    )
    add_check(
        checks,
        "Hairpin before default netmap",
        hairpin is not None and netmap_default is not None and hairpin < netmap_default,
        f"hairpin={hairpin}, default_netmap={netmap_default}",
        "critical",
    )
    return checks


def audit_service_ports(service_ports: str) -> list[dict]:
    checks = []
    sip_lines = [line.strip() for line in service_ports.splitlines() if 'name="sip"' in line]
    sip_disabled = any(" X " in f" {line} " or line.startswith("4 X") for line in sip_lines)
    add_check(
        checks,
        "MikroTik SIP helper disabled",
        sip_disabled,
        "; ".join(sip_lines) if sip_lines else "SIP helper line not found",
        "critical",
    )
    return checks


def write_outputs(outdir: Path, results: dict[str, str]) -> None:
    for idx, (command, output) in enumerate(results.items(), start=1):
        safe = command.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {command}\n\n{output}\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit MikroTik rule ordering")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    commands = collect_commands()
    results = run_commands(target, commands, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"rule_order_audit_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    write_outputs(outdir, results)

    filter_rules = parse_rules(results["/ip firewall filter print detail"])
    nat_rules = parse_rules(results["/ip firewall nat print detail"])
    checks = []
    checks.extend(audit_filter(filter_rules))
    checks.extend(audit_nat(nat_rules))
    checks.extend(audit_service_ports(results["/ip firewall service-port print detail"]))
    failures = [check for check in checks if not check["ok"]]

    summary = {
        "host": args.host,
        "filter_rule_count": len(filter_rules),
        "nat_rule_count": len(nat_rules),
        "checks": checks,
        "failure_count": len(failures),
        "failures": failures,
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
