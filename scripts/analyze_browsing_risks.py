#!/usr/bin/env python3
"""Analyze MikroTik settings that may break web browsing without changing them."""

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


def build_commands():
    return [
        "/system identity print",
        "/ip dns print",
        "/ip dns static print detail",
        "/ip firewall nat print detail",
        "/ip firewall nat print stats detail",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
        "/ip firewall mangle print detail",
        "/ip firewall service-port print detail",
        "/ip route print detail",
        "/routing rule print detail",
        "/interface print detail",
        "/interface list member print detail",
    ]


def lines_with(text: str, *needles):
    out = []
    for line in text.splitlines():
        lower = line.lower()
        if any(n.lower() in lower for n in needles):
            out.append(line.rstrip())
    return out


def dns_findings(dns_runtime: str, dns_static: str):
    findings = []
    if "allow-remote-requests: yes" in dns_runtime:
        findings.append("DNS resolver is open to router clients (allow-remote-requests=yes); OK for LAN use, risky if input filter exposes UDP/TCP 53 from WAN.")
    if "use-doh-server:" in dns_runtime and "https://" in dns_runtime:
        findings.append("DNS uses DoH. If certificate/time/DoH endpoint fails, general browsing DNS can fail even if IP routing is healthy.")
    if "verify-doh-cert: yes" in dns_runtime:
        findings.append("DoH certificate verification is enabled; system clock and CA trust must be correct.")
    if "type=FWD" in dns_static:
        findings.append("DNS has static FWD rules. Domains matching those rules depend on the configured forward-to servers.")
    if "regexp=" in dns_static:
        findings.append("DNS static still has regexp rules; broad or inefficient regex can unexpectedly capture domains.")

    fwd_lines = lines_with(dns_static, "type=FWD")
    disabled_fwd = [l for l in fwd_lines if " X " in f" {l} "]
    if disabled_fwd:
        findings.append(f"DNS has {len(disabled_fwd)} disabled FWD rule(s); confirm they are intentionally disabled.")
    return findings


def nat_findings(nat_detail: str):
    findings = []
    if "action=netmap" in nat_detail:
        findings.append("NAT uses netmap rules for outbound traffic. Incorrect ordering or overly broad netmap can affect source IP selection and site sessions.")
    if "dst-port=80,443" in nat_detail and "dstnat" in nat_detail:
        findings.append("There are HTTP/HTTPS dstnat rules. Internal users may need matching hairpin srcnat when accessing public IPs/domains.")
    if "action=masquerade" not in nat_detail and "action=netmap" not in nat_detail:
        findings.append("No obvious outbound srcnat/netmap found; clients behind private networks may fail to browse externally.")

    broad_default = lines_with(nat_detail, "masquerade-by-default", "out-interface-list=WAN")
    if broad_default:
        findings.append("A broad default WAN NAT rule exists; verify specific netmap rules above it are ordered as intended.")
    return findings


def filter_findings(filter_detail: str):
    findings = []
    if "fasttrack-connection" in filter_detail:
        findings.append("FastTrack is enabled. It can bypass mangle/queue processing for established traffic; usually OK, but relevant for policy routing/QoS/debug.")
    if "drop invalid" in filter_detail:
        findings.append("Invalid packet drops are enabled. MTU/asymmetric routing issues may surface as browsing stalls if connections become invalid.")
    if "drop all from WAN not DSTNATed" in filter_detail:
        findings.append("WAN new traffic is dropped unless dstnat is present; expected perimeter behavior.")
    return findings


def mangle_findings(mangle_detail: str):
    findings = []
    if "change-mss" in mangle_detail:
        disabled = [l for l in lines_with(mangle_detail, "change-mss") if " X " in f" {l} "]
        if disabled:
            findings.append("TCP MSS clamp rules exist but are disabled. PPPoE/VPN/VXLAN paths may break some HTTPS sites if MTU is tight.")
        else:
            findings.append("TCP MSS clamp rules are enabled; useful for PPPoE/VPN paths.")
    if "mark-routing" in mangle_detail:
        findings.append("Routing marks exist; browsing may depend on policy routing consistency.")
    return findings


def service_port_findings(service_ports: str):
    findings = []
    sip_lines = lines_with(service_ports, 'name="sip"')
    if sip_lines:
        if any(" X " not in f" {line} " for line in sip_lines):
            findings.append("MikroTik SIP helper is enabled; it can break SIP behind NAT and occasionally disturb related UDP flows.")
        else:
            findings.append("MikroTik SIP helper is disabled; good for explicit SIP NAT deployments.")
    return findings


def interface_findings(interface_detail: str):
    findings = []
    mtu_lines = lines_with(interface_detail, "mtu=", "actual-mtu=", "l2mtu=")
    low_mtu = []
    for line in mtu_lines:
        for match in re.finditer(r"(?:actual-)?mtu=(\d+)", line):
            if int(match.group(1)) < 1500:
                low_mtu.append(line.strip())
                break
    if low_mtu:
        findings.append(f"Found {len(low_mtu)} interface line(s) with MTU below 1500; check MSS/PMTUD for web browsing over those paths.")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Analyze browsing-breakage risks on MikroTik")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    cmd_list = build_commands()
    out = run_commands(target, cmd_list, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"browsing_risks_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmd_list, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    findings = []
    findings.extend(dns_findings(out["/ip dns print"], out["/ip dns static print detail"]))
    findings.extend(nat_findings(out["/ip firewall nat print detail"]))
    findings.extend(filter_findings(out["/ip firewall filter print detail"]))
    findings.extend(mangle_findings(out["/ip firewall mangle print detail"]))
    findings.extend(service_port_findings(out["/ip firewall service-port print detail"]))
    findings.extend(interface_findings(out["/interface print detail"]))

    summary = {
        "host": args.host,
        "finding_count": len(findings),
        "findings": findings,
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
