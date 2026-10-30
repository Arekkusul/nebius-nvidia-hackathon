#!/usr/bin/env bash
# Publish the hosted demo to a Hugging Face Space (Docker SDK).
#
#   HF_TOKEN=hf_xxx ./deploy/huggingface/push_space.sh <user>/<space-name>
#
# Needs: HF_TOKEN, a Hugging Face token with write access; the Space id as the only argument,
# already created on the Hub with the Docker SDK (the Dockerfile at the repository root is
# what the Space builds); git and rsync on this machine.
#
# What it does: clones the Space repository into a temp directory (or starts an empty one when
# the Space has no commits yet), mirrors this working tree into it minus local state and
# non-runtime files (runs/, virtualenvs, tests, docs), puts the Space card
# (deploy/huggingface/README.md) in place of the project README, commits and pushes to main.
# Re-running with no changes is harmless: the empty commit is skipped and the push is a no-op.
# Secrets (NEBIUS_API_KEY, TAVILY_API_KEY, RULESMITH_DEMO_LOCKED) are set in the Space settings,
# never pushed. For a free static Space see build_static.py instead.
set -euo pipefail
SPACE="${1:?usage: push_space.sh <user>/<space>}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
git clone "https://user:${HF_TOKEN:?set HF_TOKEN}@huggingface.co/spaces/${SPACE}" "$TMP" 2>/dev/null || git -C "$TMP" init
rsync -a --delete --exclude .git --exclude runs --exclude .venv --exclude venv --exclude tests --exclude docs "$ROOT/" "$TMP/"
cp "$ROOT/deploy/huggingface/README.md" "$TMP/README.md"
cd "$TMP"
git add -A
git -c user.name=rulesmith -c user.email=rulesmith@users.noreply.huggingface.co commit -m "deploy RuleSmith" >/dev/null || true
git push "https://user:${HF_TOKEN}@huggingface.co/spaces/${SPACE}" HEAD:main
echo "pushed to https://huggingface.co/spaces/${SPACE}"
