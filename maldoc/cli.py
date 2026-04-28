"""Command-line interface for MalDoc Scanner."""

import argparse
import sys
from pathlib import Path

from maldoc import __version__
from maldoc.analyzer import analyze_office, analyze_pdf
from maldoc.ole import extract_vba
from maldoc.output import print_json, print_text
from maldoc.pdf import extract_pdf_features


def _detect_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in (".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx", ".pptm", ".rtf"):
        return "office"
    if suffix == ".pdf":
        return "pdf"
    return "unknown"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="maldoc",
        description="Static analyzer for malicious Office docs and PDFs.",
    )
    p.add_argument("--version", action="version", version=f"maldoc {__version__}")
    p.add_argument("--file", required=True, help="Path to file to analyze")
    p.add_argument(
        "--type",
        choices=["office", "pdf", "auto"],
        default="auto",
        help="Force document type (default: auto-detect by extension)",
    )
    p.add_argument(
        "--from-text",
        action="store_true",
        help="Treat --file as already-extracted text (skip oletools/pypdf). "
        "Pair with --type to choose the indicator catalog.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON output")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.file)
    if not path.exists():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    doc_type = args.type if args.type != "auto" else _detect_type(path)
    if doc_type == "unknown":
        print(
            f"error: cannot infer document type from extension. "
            f"Pass --type office|pdf to force.",
            file=sys.stderr,
        )
        return 2

    if args.from_text:
        content = path.read_text(errors="replace")
        notes = ["input read as raw text — extraction step skipped"]
    elif doc_type == "office":
        content, notes = extract_vba(path)
    else:
        content, notes = extract_pdf_features(path)

    if doc_type == "office":
        report = analyze_office(content, source=str(path), notes=notes)
    else:
        report = analyze_pdf(content, source=str(path), notes=notes)

    color = not args.no_color and sys.stdout.isatty()
    if args.json:
        print_json(report)
    else:
        print_text(report, color=color)

    return 1 if report.severity == "high" else 0


if __name__ == "__main__":
    sys.exit(main())
