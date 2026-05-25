#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults, write_command_outputs


TARGET_DST = "10.80.0.254"
SUSPECT_SRC_NET = "10.0.3.0/24"


def mikrotik_diag_commands(dst: str):
    return [
        "/system identity print",
        "/ip address print detail",
        "/ip route print detail where dst-address~\"10.0.3.0/24|10.80.0.0/16|0.0.0.0/0\"",
        "/routing rule print detail",
        "/ip firewall filter print detail",
        "/ip firewall nat print detail",
        "/ip firewall mangle print detail",
        "/ip firewall connection print count-only",
        f"/ping {dst} count=8",
        f"/tool traceroute {dst}",
    ]


def summarize(outputs: dict) -> str:
    lines = []
    route_out = outputs.get('/ip route print detail where dst-address~"10.0.3.0/24|10.80.0.0/16|0.0.0.0/0"', "")
    ping_out = outputs.get(f"/ping {TARGET_DST} count=8", "")
    trace_out = outputs.get(f"/tool traceroute {TARGET_DST}", "")

    lines.append(f"Rede investigada: {SUSPECT_SRC_NET}")
    lines.append(f"Destino investigado: {TARGET_DST}")
    lines.append("")
    lines.append("## Sinais de rota")
    if "10.80.0.0/16" in route_out or TARGET_DST in route_out:
        lines.append("- Há rota explícita para a faixa 10.80.0.0/16 (ou destino relacionado).")
    else:
        lines.append("- Não apareceu rota explícita para 10.80.0.0/16; tráfego pode estar saindo por default route.")

    lines.append("")
    lines.append("## Sinais de conectividade")
    if "sent=" in ping_out and "received=0" in ping_out:
        lines.append("- Ping do roteador para 10.80.0.254 falhou (0 respostas).")
    elif "sent=" in ping_out:
        lines.append("- Ping do roteador para 10.80.0.254 teve respostas.")
    else:
        lines.append("- Saída de ping inconclusiva.")

    if " 1 " in trace_out:
        lines.append("- Traceroute coletado; ver arquivo bruto para saltos e ponto de perda.")
    else:
        lines.append("- Traceroute inconclusivo ou não suportado no equipamento.")

    lines.append("")
    lines.append("## Próximo foco")
    lines.append("- Validar forward/return path entre 10.0.3.0/24 e 10.80.0.254 em ambos roteadores.")
    lines.append("- Confirmar se há regra de firewall/mangle/NAT impactando essa origem/destino.")
    return "\n".join(lines) + "\n"


def main():
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_base = Path("reports") / f"diagnose_{timestamp}"
    out_base.mkdir(parents=True, exist_ok=True)

    for target in inventory:
        dtype = target.get("type", "").strip().lower()
        host = target.get("host", "").strip()
        if dtype != "mikrotik" or not host:
            continue

        print(f"[+] Diagnosticando {host}...")
        host_dir = out_base / host.replace(".", "_")
        cmds = mikrotik_diag_commands(TARGET_DST)
        try:
            outputs = run_commands(target, cmds, defaults)
            write_command_outputs(host_dir, outputs)
            (host_dir / "SUMMARY.md").write_text(summarize(outputs), encoding="utf-8")
        except Exception as err:
            host_dir.mkdir(parents=True, exist_ok=True)
            (host_dir / "00_connection_error.txt").write_text(str(err), encoding="utf-8")
            print(f"[!] Falha em {host}: {err}")

    print(f"[OK] Diagnóstico salvo em {out_base}")


if __name__ == "__main__":
    main()
