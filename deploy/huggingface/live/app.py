"""Hugging Face Space entry point for the live RuleSmith demo.

Spaces created with ``sdk: gradio`` run ``python app.py`` on a free CPU and
expose port 7860. RuleSmith is a FastAPI app, so this file starts it with
uvicorn on that port; the Space does not need Gradio itself.

requirements.txt installs the package and its dependencies from GitHub at
build time. The data files the validator needs (benign corpus, SigmaHQ
index, ATT&CK index) and the recorded replays live next to the package in
the repository, not inside the wheel, so at start-up this file clones the
repository once and runs the app from that checkout.

Secrets to set on the Space: NEBIUS_API_KEY (required), TAVILY_API_KEY
(optional, enables URL extraction and search mode) and, to keep a public
demo affordable, RULESMITH_DEMO_BUDGET_USD (for example 5), which caps the
live spend per process; recorded replays keep working once it is spent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = os.environ.get("RULESMITH_REPO", "https://github.com/Arekkusul/nebius-nvidia-hackathon.git")
REF = os.environ.get("RULESMITH_REF", "main")
CHECKOUT = Path("/tmp/rulesmith-src")


def ensure_checkout() -> Path:
    """Clone the repository (shallow) unless a checkout is already present."""
    if not (CHECKOUT / "rulesmith").is_dir():
        subprocess.run(["git", "clone", "--depth", "1", "--branch", REF, REPO, str(CHECKOUT)], check=True)
    return CHECKOUT


if __name__ == "__main__":
    src = ensure_checkout()
    # Import the package from the checkout so data/ and examples/ resolve relative to it.
    sys.path.insert(0, str(src))
    os.chdir(src)
    os.environ.setdefault("RULESMITH_RUNS_DIR", "/tmp/rulesmith-runs")

    import uvicorn

    uvicorn.run("rulesmith.server.app:app", host="0.0.0.0", port=int(os.environ.get("PORT", "7860")), log_level="info")
