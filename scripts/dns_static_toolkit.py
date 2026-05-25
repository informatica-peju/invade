#!/usr/bin/env python3
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
    raise ValueError(f"Host {host} não encontrado no inventário")


def parse_dns_static_detail(text: str):
    entry_lines = [ln.strip() for ln in text.splitlines() if re.match(r"^\s*\d+\s", ln)]
    kv_re = re.compile(r"([a-zA-Z0-9-]+)=(\"[^\"]*\"|\S+)")
    entries = []
    for ln in entry_lines:
        disabled = " X " in f" {ln} "
        data = {}
        for k, v in kv_re.findall(ln):
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            data[k] = v
        if "type" not in data:
            continue
        data["disabled"] = "yes" if disabled else "no"
        entries.append(data)
    return entries


def normalize_entries(entries):
    # Convert simple regex suffix FWD (.*domain\.tld$) into name + match-subdomain=yes.
    simple_suffix_re = re.compile(r"^\.\*([A-Za-z0-9\\.-]+)\$$")
    converted = 0
    for e in entries:
        if e.get("type") == "FWD" and "regexp" in e:
            m = simple_suffix_re.match(e["regexp"])
            if m:
                domain = m.group(1).replace("\\.", ".")
                e.pop("regexp", None)
                e["name"] = domain
                e["match-subdomain"] = "yes"
                converted += 1

    key_fields = [
        "disabled",
        "type",
        "ttl",
        "name",
        "regexp",
        "match-subdomain",
        "forward-to",
        "address",
        "cname",
        "ns",
        "srv-priority",
        "srv-weight",
        "srv-port",
        "srv-target",
    ]
    seen = set()
    uniq = []
    for e in entries:
        key = tuple((k, e.get(k, "")) for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(e)

    uniq.sort(
        key=lambda e: (
            0 if e.get("disabled") == "no" else 1,
            e.get("type", ""),
            e.get("name", e.get("regexp", "")),
            e.get("forward-to", e.get("address", e.get("cname", ""))),
        )
    )
    return uniq, converted, len(entries) - len(uniq)


def to_add_commands(entries):
    def q(v):
        return '"' + str(v).replace('"', '\\"') + '"'

    add_cmds = []
    for e in entries:
        parts = ["/ip dns static add"]
        if e.get("disabled") == "yes":
            parts.append("disabled=yes")
        if e.get("ttl"):
            parts.append(f"ttl={e['ttl']}")
        parts.append(f"type={e['type']}")
        for f in [
            "name",
            "regexp",
            "match-subdomain",
            "forward-to",
            "address",
            "cname",
            "ns",
            "srv-priority",
            "srv-weight",
            "srv-port",
            "srv-target",
        ]:
            if f in e and e[f] != "":
                val = e[f]
                if f in {"srv-priority", "srv-weight", "srv-port", "match-subdomain"}:
                    parts.append(f"{f}={val}")
                else:
                    parts.append(f"{f}={q(val)}")
        add_cmds.append(" ".join(parts))
    return add_cmds


def action_backup(host: str):
    target, defaults = get_target(host)
    out = run_commands(target, ["/ip dns print", "/ip dns static print detail", "/ip dns cache print count-only"], defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"dns_{host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    (outdir / "dns_runtime.txt").write_text(out["/ip dns print"] + "\n", encoding="utf-8")
    (outdir / "dns_static.txt").write_text(out["/ip dns static print detail"] + "\n", encoding="utf-8")
    (outdir / "dns_cache_count.txt").write_text(out["/ip dns cache print count-only"] + "\n", encoding="utf-8")

    entries = parse_dns_static_detail(out["/ip dns static print detail"])
    summary = {"entries_total": len(entries)}
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[OK] Backup salvo em {outdir}")


def action_normalize_apply(host: str):
    target, defaults = get_target(host)
    original = run_commands(target, ["/ip dns static print detail"], defaults)["/ip dns static print detail"]
    entries = parse_dns_static_detail(original)
    normalized, converted, removed_duplicates = normalize_entries(entries)
    add_cmds = to_add_commands(normalized)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"dns_rebuild_{host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "before_dns_static_detail.txt").write_text(original + "\n", encoding="utf-8")
    (outdir / "rebuild_commands.rsc").write_text("\n".join(add_cmds) + "\n", encoding="utf-8")

    cmds = ["/ip dns static print count-only", "/ip dns static remove [find]"] + add_cmds + ["/ip dns static print count-only"]
    run_commands(target, cmds, defaults)
    after = run_commands(target, ["/ip dns static print detail", "/ip dns static print count-only"], defaults)

    (outdir / "after_dns_static_detail.txt").write_text(after["/ip dns static print detail"] + "\n", encoding="utf-8")
    summary = {
        "original_entries": len(entries),
        "final_entries": len(normalized),
        "converted_regex_to_match_subdomain": converted,
        "removed_duplicates": removed_duplicates,
        "after_count": after["/ip dns static print count-only"].strip(),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[OK] Normalização aplicada. Artefatos em {outdir}")
    print(json.dumps(summary, ensure_ascii=False))


def action_test(host: str):
    target, defaults = get_target(host)
    test_domains = [
        "services.pmpejucara.rs.gov.br",
        "chat.pmpejucara.rs.gov.br",
        "smb.pmpejucara.rs.gov.br",
        "www.jus.br",
        "portal.ufal.br",
        "www.google.com",
    ]

    cmds = ["/ip dns static print detail"]
    cmds += [f':do {{ :put [:resolve "{d}"] }} on-error={{ :put "ERR:{d}" }}' for d in test_domains]
    out = run_commands(target, cmds, defaults)

    static = out["/ip dns static print detail"]
    print(f"regexp_present={ 'regexp=' in static }")
    for d in test_domains:
        k = f':do {{ :put [:resolve "{d}"] }} on-error={{ :put "ERR:{d}" }}'
        print(f"{d} => {out[k].strip()}")


def main():
    parser = argparse.ArgumentParser(description="DNS static toolkit for MikroTik")
    parser.add_argument("action", choices=["backup", "normalize-apply", "test"])
    parser.add_argument("--host", required=True, help="Target host in inventory")
    args = parser.parse_args()

    if args.action == "backup":
        action_backup(args.host)
    elif args.action == "normalize-apply":
        action_normalize_apply(args.host)
    elif args.action == "test":
        action_test(args.host)


if __name__ == "__main__":
    main()
