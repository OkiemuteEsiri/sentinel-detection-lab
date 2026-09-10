from __future__ import annotations
import argparse
from pathlib import Path
from .detections import run_all
from .io import load_events, render_markdown

def main() -> int:
    parser=argparse.ArgumentParser(description="Run synthetic Sentinel-style defensive detections")
    parser.add_argument("input", help="Path to synthetic event JSON")
    parser.add_argument("--output", default="reports/generated-assessment.md")
    args=parser.parse_args()
    events=load_events(args.input)
    report=render_markdown(run_all(events))
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(report,encoding="utf-8")
    print(f"Wrote {out}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
