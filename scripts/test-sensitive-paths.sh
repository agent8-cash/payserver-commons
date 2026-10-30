#!/usr/bin/env bash
# Checks that scripts/sensitive-paths.sh flags every path it should and
# nothing else, against a real git diff.
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/sensitive-paths.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Must be flagged: sensitive directory at any depth, key-derivation names in
# any path segment, and the original basename keywords.
flagged=(
  crypto/keys.rs
  module/crypto/keys.rs
  auth/session.rs
  nested/auth/thing.rs
  scrub/rules.rs
  wallet/derivation/address.rs
  some_kdf_helper.rs
)

# Must not be flagged: "auth", "crypto" or "scrub" only as a substring of a
# segment, and unrelated paths.
clean=(
  foo/author.rs
  authors/list.rs
  authority.rs
  scrubbing-notes.md
  bar/baz.rs
)

repo="$work/repo"
git init -q "$repo"
cd "$repo"
git -c user.name=test -c user.email=test@example.invalid commit -q --allow-empty -m base
base="$(git rev-parse HEAD)"

for f in "${flagged[@]}" "${clean[@]}"; do
  mkdir -p "$(dirname "$f")"
  echo x > "$f"
done
git add -- "${flagged[@]}" "${clean[@]}"
git -c user.name=test -c user.email=test@example.invalid commit -q -m head
head="$(git rev-parse HEAD)"

if ! actual="$("$script" "$base" "$head")"; then
  echo "FAIL: sensitive-paths.sh exited non-zero (it must always exit 0)" >&2
  exit 1
fi

expected="$(printf '%s\n' "${flagged[@]}" | sort)"
actual="$(printf '%s\n' "$actual" | sed '/^$/d' | sort)"

if [ "$actual" != "$expected" ]; then
  echo "FAIL: flagged paths differ from expected (< expected, > actual)" >&2
  diff <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
  exit 1
fi

echo "ok: flagged ${#flagged[@]} sensitive paths, skipped ${#clean[@]} others"
