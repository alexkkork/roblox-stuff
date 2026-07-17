#!/bin/zsh
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIRROR="$HOME/Library/Application Support/RobloxStuffSync/repo"
LOCK="${TMPDIR:-/tmp}/roblox-stuff-auto-sync.lock"
LOG="$HOME/Library/Logs/roblox-stuff-auto-sync.log"

mkdir -p "$(dirname "$LOG")"
if ! mkdir "$LOCK" 2>/dev/null; then
    printf '%s skipped: another sync is running\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
    exit 0
fi
trap 'rmdir "$LOCK" 2>/dev/null || true' EXIT

mkdir -p "$MIRROR"
rsync -a --delete \
    --exclude='.git/' \
    --exclude='.DS_Store' \
    --exclude='.codex/' \
    --exclude='.secrets/' \
    --exclude='keys/*.private' \
    --exclude='.env' \
    --exclude='.env.local' \
    --exclude='.env.production' \
    --exclude='.vercel/' \
    --exclude='build/' \
    --exclude='build-*/' \
    --exclude='dist/' \
    --exclude='bin/' \
    --exclude='obj/' \
    --exclude='publish/' \
    --exclude='node_modules/' \
    --exclude='*.dSYM/' \
    --exclude='*.zip' \
    --exclude='*.tar.gz' \
    --exclude='captures/' \
    --exclude='outputs/' \
    --exclude='work/' \
    --exclude='*.trace' \
    --exclude='*.log' \
    --exclude='*.tmp' \
    "$ROOT/" "$MIRROR/"

cd "$MIRROR"
if [[ ! -d .git ]]; then
    git init -b main >> "$LOG" 2>&1
fi
git add -A

if git diff --cached --quiet; then
    printf '%s clean\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
    exit 0
fi

secret_pattern='ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(^|[^A-Za-z])(VERCEL_TOKEN|BLOB_READ_WRITE_TOKEN|REDIS_URL)[[:space:]]*='
if git grep --cached -I -n -E "$secret_pattern" -- . \
    ':(exclude)**/.env.example' \
    ':(exclude)**/*.test.*' >> "$LOG" 2>/dev/null; then
    printf '%s blocked: possible credential in staged files\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
    exit 2
fi

while IFS= read -r file; do
    [[ -z "$file" || ! -f "$file" ]] && continue
    bytes=$(stat -f '%z' "$file")
    if (( bytes > 50000000 )); then
        printf '%s blocked: staged file exceeds 50 MB: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$file" >> "$LOG"
        exit 3
    fi
done < <(git diff --cached --name-only --diff-filter=ACMR)

git commit -m "auto save $(date '+%Y-%m-%d %H:%M')" >> "$LOG" 2>&1
git push origin HEAD:main >> "$LOG" 2>&1
printf '%s pushed\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG"
