#!/usr/bin/env python3
# Vespera — insert or replace Vespera blocks in ossec.conf (before </ossec_config>).
# Usage: vespera-merge-ossec.py INPUT_CONF OUTPUT_CONF --vespera-root DIR [--non-interactive]

import argparse
import pathlib
import re
import sys

MARK_BEGIN = "<!-- VESPERA_BEGIN -->"
MARK_END = "<!-- VESPERA_END -->"


def build_block(root: pathlib.Path) -> str:
    integ = root / "config" / "ossec-integration.xml"
    ar = root / "config" / "ossec-active-response.xml"
    if not integ.is_file() or not ar.is_file():
        print(f"Missing {integ} or {ar}", file=sys.stderr)
        sys.exit(1)
    parts = [
        "",
        MARK_BEGIN,
        integ.read_text(encoding="utf-8", errors="replace").strip(),
        "",
        ar.read_text(encoding="utf-8", errors="replace").strip(),
        "",
        MARK_END,
        "",
    ]
    return "\n".join(parts)


def fix_double_ossec_config(conf_text: str) -> str:
    """Merge multiple <ossec_config> blocks into one (analysisd only parses the first)."""
    closing = "</ossec_config>"
    opening = "<ossec_config>"
    parts = conf_text.split(closing)
    # parts = [block1, block2, ..., trailing]
    if len(parts) <= 2:
        return conf_text  # single block, nothing to do

    # Merge: keep first block open, append inner content of all subsequent blocks
    merged = parts[0]
    for extra in parts[1:-1]:  # skip last (trailing after final </ossec_config>)
        inner = extra
        idx = inner.find(opening)
        if idx >= 0:
            inner = inner[idx + len(opening):]
        merged += inner
    merged += closing + "\n"
    return merged


def has_untagged_integration(conf_text: str) -> bool:
    """Return True if ossec.conf has <integration> blocks NOT wrapped in VESPERA markers."""
    if MARK_BEGIN in conf_text and MARK_END in conf_text:
        return False  # already managed by Vespera, safe to replace
    return bool(re.search(r"<integration>", conf_text))


def merge(conf_text: str, block: str, non_interactive: bool = False) -> str:
    # Fix double blocks first
    conf_text = fix_double_ossec_config(conf_text)

    if MARK_BEGIN in conf_text and MARK_END in conf_text:
        # Idempotent update — replace existing Vespera block
        pat = re.compile(
            re.escape(MARK_BEGIN) + r".*?" + re.escape(MARK_END),
            re.DOTALL,
        )
        new_text, n = pat.subn(block.strip() + "\n", conf_text, count=1)
        if n != 1:
            print("Could not replace existing Vespera block.", file=sys.stderr)
            sys.exit(1)
        return new_text

    # First-time insertion — check for conflicting <integration> blocks
    if has_untagged_integration(conf_text):
        print(
            "\n⚠  WARNING: ossec.conf already contains <integration> blocks not managed by Vespera.",
            file=sys.stderr,
        )
        print(
            "   Merging will ADD Vespera integrations alongside existing ones.",
            file=sys.stderr,
        )
        if not non_interactive:
            print(
                "   Options:\n"
                "     1) Merge — add Vespera blocks alongside existing ones (recommended)\n"
                "     2) Cancel — abort and edit ossec.conf manually",
                file=sys.stderr,
            )
            choice = input("   Choice [1]: ").strip() or "1"
            if choice != "1":
                print("Aborted by user.", file=sys.stderr)
                sys.exit(2)
        else:
            print("   --non-interactive: proceeding with merge.", file=sys.stderr)

    close = "</ossec_config>"
    idx = conf_text.rfind(close)
    if idx == -1:
        print("No closing </ossec_config> found in ossec.conf.", file=sys.stderr)
        sys.exit(1)
    return conf_text[:idx] + block + conf_text[idx:]


def main() -> None:
    p = argparse.ArgumentParser(description="Merge Vespera XML into Wazuh ossec.conf")
    p.add_argument("input_conf", type=pathlib.Path)
    p.add_argument("output_conf", type=pathlib.Path)
    p.add_argument("--vespera-root", type=pathlib.Path, required=True)
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Skip interactive prompts (for CI / --quick installs)",
    )
    args = p.parse_args()

    conf = args.input_conf.read_text(encoding="utf-8", errors="replace")
    block = build_block(args.vespera_root)
    out = merge(conf, block, non_interactive=args.non_interactive)
    args.output_conf.write_text(out, encoding="utf-8")
    print("ossec.conf updated.")


if __name__ == "__main__":
    main()
