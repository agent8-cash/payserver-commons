#!/usr/bin/env bash
# Prints the files a diff changes that a human must review before merge:
# crypto, auth, scrub-rule code, and key-derivation modules. Prints nothing
# when the diff is clear. Always exits 0: this flags, it does not gate.
#
# Usage: scripts/sensitive-paths.sh <base-sha> <head-sha>
set -euo pipefail

base="${1:?usage: sensitive-paths.sh <base-sha> <head-sha>}"
head="${2:?usage: sensitive-paths.sh <base-sha> <head-sha>}"

git diff --name-only "$base...$head" \
  | grep -E '^(crypto|auth|scrub)/|(^|/)auth/|(^|/)[^/]*(kdf|derive|argon)[^/]*$' \
  || true
