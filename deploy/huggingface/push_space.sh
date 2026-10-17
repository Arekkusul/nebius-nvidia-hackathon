#!/usr/bin/env bash
# Publish the hosted demo to a Hugging Face Space (Docker SDK).
#   HF_TOKEN=hf_xxx ./deploy/huggingface/push_space.sh <user>/<space-name>
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
