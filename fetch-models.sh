#!/usr/bin/env bash
# Restore the model checkpoints under server/models/.
#
# All three files SHIP WITH THIS HANDOFF, so you should not normally need this
# script. Use it only if a checkpoint was deleted, truncated, or corrupted (for
# example by a zip that was cut short): it re-downloads whatever is missing or
# fails its checksum, and leaves correct files alone.
#
#   ./fetch-models.sh          # check, and download only what is wrong
#   ./fetch-models.sh --check  # check only, download nothing
#
# The server refuses to start without files 1 and 2; file 3 (stories110M.bin) is
# what distinf_sim.py --model 3 and weightfetch_regression_test.py need.
set -euo pipefail
cd "$(dirname "$0")"
DEST=server/models
mkdir -p "$DEST"

TINYLLAMAS=https://huggingface.co/karpathy/tinyllamas/resolve/main
LLAMA2C=https://github.com/karpathy/llama2.c/raw/master

# name | bytes | sha256 | url
FILES=(
  "tokenizer.bin|433869|50a52ef822ee9e83de5ce9d0be0a025a773d019437f58b5ff9dcafb063ece361|$LLAMA2C/tokenizer.bin"
  "stories15M.bin|60816028|cd590644d963867a2b6e5a1107f51fad663c41d79c149fbecbbb1f95fa81f49a|$TINYLLAMAS/stories15M.bin"
  "stories110M.bin|438381596|515267168726a1ed1317a64a408492e6af3b67c1f71c5bd98c01d9d721803a24|$TINYLLAMAS/stories110M.bin"
)

check_only=0
[ "${1:-}" = "--check" ] && check_only=1

ok=1
for row in "${FILES[@]}"; do
  IFS='|' read -r name bytes sha url <<< "$row"
  path="$DEST/$name"
  if [ -f "$path" ] \
     && [ "$(stat -c %s "$path")" = "$bytes" ] \
     && [ "$(sha256sum "$path" | cut -d' ' -f1)" = "$sha" ]; then
    echo "OK      $name ($bytes bytes)"
    continue
  fi
  if [ "$check_only" = 1 ]; then
    echo "BAD     $name (missing, wrong size, or wrong checksum)"
    ok=0
    continue
  fi
  echo "FETCH   $name from $url"
  curl -fL --retry 3 -o "$path.part" "$url"
  got=$(sha256sum "$path.part" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    rm -f "$path.part"
    echo "FAIL    $name: sha256 mismatch (got $got, expected $sha)" >&2
    exit 1
  fi
  mv "$path.part" "$path"
  echo "OK      $name restored ($bytes bytes)"
done

[ "$ok" = 1 ] || { echo "one or more checkpoints are bad; re-run without --check" >&2; exit 1; }
echo "all three checkpoints present and verified in $DEST"
