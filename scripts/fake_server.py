"""Serve the RuleSmith UI backed by the scripted fake model.

Used by scripts/ui_smoke.js to drive a complete live run in a headless
browser without a Token Factory key: the FakeLLM answers every stage from
the fixtures the offline test-suite uses, so the run finishes in well under
a second and the UI goes through the same events a real run produces.

    python scripts/fake_server.py [--port 7862]
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

# Make the repository importable when the script is run from anywhere.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import uvicorn

from rulesmith.config import Settings
from rulesmith.llm import FakeLLM
from rulesmith.server.app import create_app
from tests.fixtures import responses_all_good


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=7862)
    args = parser.parse_args()
    runs_dir = Path(tempfile.mkdtemp(prefix="rulesmith-fake-"))
    # A placeholder Tavily key keeps the Search tab enabled so the smoke test can see it.
    app = create_app(Settings(runs_dir=runs_dir, tavily_api_key="fake"), llm=FakeLLM(responses_all_good()))
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
