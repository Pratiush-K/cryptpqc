"""Command-line interface: `crypt scan <path>` and `crypt bench`."""
import argparse
import json
import sys
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from . import __version__
from .scanner import risk_label, risk_score, scan_path

SEVERITY_STYLE = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan"}


def cmd_scan(args) -> int:
    try:
        findings = scan_path(args.path)
    except FileNotFoundError as err:
        print(err, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return 1 if findings else 0

    console = Console()
    if not findings:
        console.print("[bold green]No quantum-vulnerable cryptography found.[/]")
        return 0

    table = Table(title=f"Crypt scan: {args.path}")
    table.add_column("Severity")
    table.add_column("Location")
    table.add_column("Algorithm")
    table.add_column("Recommended fix")
    for f in findings:
        style = SEVERITY_STYLE[f.severity]
        table.add_row(f"[{style}]{f.severity}[/]", f"{f.file}:{f.line}", f.algorithm, f.fix)
    console.print(table)

    score = risk_score(findings)
    console.print(
        f"\nRisk score: [bold]{score}/100[/] ({risk_label(score)}), "
        f"{len(findings)} finding(s)"
    )
    return 1


def cmd_bench(args) -> int:
    from .bench import run_benchmarks, save_chart, save_json

    console = Console()
    console.print(f"Running benchmarks ({args.iterations} iterations each)...")
    data = run_benchmarks(iterations=args.iterations)

    table = Table(title="Key exchange benchmark (median per operation)")
    table.add_column("Scheme")
    table.add_column("Keygen ms", justify="right")
    table.add_column("Encrypt ms", justify="right")
    table.add_column("Decrypt ms", justify="right")
    table.add_column("Public key B", justify="right")
    table.add_column("Ciphertext B", justify="right")
    table.add_column("Quantum-safe")
    for name, r in data["results"].items():
        safe = "[green]yes[/]" if r["quantum_safe"] else "[red]no[/]"
        table.add_row(
            name,
            f"{r['keygen_ms']:.3f}",
            f"{r['encaps_ms']:.3f}",
            f"{r['decaps_ms']:.3f}",
            str(r["public_key_bytes"]),
            str(r["ciphertext_bytes"]),
            safe,
        )
    console.print(table)
    console.print(f"[dim]{data['note']}[/]")

    if args.json:
        save_json(data, args.json)
        console.print(f"Saved results to {args.json}")
    if args.chart:
        save_chart(data, args.chart)
        console.print(f"Saved chart to {args.chart}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypt", description="Crypt: post-quantum migration toolkit"
    )
    parser.add_argument("--version", action="version", version=f"crypt {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Find quantum-vulnerable cryptography")
    scan.add_argument("path", help="File or folder to scan")
    scan.add_argument("--json", action="store_true", help="Print JSON output")
    scan.set_defaults(func=cmd_scan)

    bench = sub.add_parser("bench", help="Benchmark RSA, X25519, ML-KEM and the hybrid")
    bench.add_argument("--iterations", type=int, default=50, help="Runs per measurement")
    bench.add_argument("--json", metavar="PATH", help="Save results as JSON")
    bench.add_argument("--chart", metavar="PATH", help="Save a PNG chart (needs matplotlib)")
    bench.set_defaults(func=cmd_bench)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())