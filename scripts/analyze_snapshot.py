#!/usr/bin/env python3
from pathlib import Path


def main():
    base = Path("data/raw")
    if not base.exists():
        print("Nenhum snapshot encontrado em data/raw")
        return

    snapshots = sorted([p for p in base.iterdir() if p.is_dir()])
    if not snapshots:
        print("Nenhum snapshot encontrado em data/raw")
        return

    latest = snapshots[-1]
    report = Path("reports") / f"summary_{latest.name}.md"

    lines = [f"# Resumo de Snapshot: {latest.name}", ""]
    for host_dir in sorted([d for d in latest.iterdir() if d.is_dir()]):
        files = list(host_dir.glob("*.txt"))
        lines.append(f"## Host {host_dir.name}")
        lines.append(f"- Arquivos coletados: {len(files)}")

        conn_err = host_dir / "00_connection_error.txt"
        if conn_err.exists():
            lines.append("- Status: erro de conexão")
        else:
            lines.append("- Status: coleta concluída")
        lines.append("")

    report.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] Relatório gerado em {report}")


if __name__ == "__main__":
    main()
