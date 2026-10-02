"""Command-line interface: `crypt scan <path>`."""
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