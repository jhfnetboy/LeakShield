#!/usr/bin/env bash
#
# Regression test for hooks/pre-commit secret detection.
# Verifies (a) the patterns actually fire (ERE braces), and (b) a bare bytes32
# is NOT a false positive. Run from the repo root: bash test/test-detection.sh
#
set -u
HOOK="$(cd "$(dirname "$0")/.." && pwd)/hooks/pre-commit"
PASS=0
FAIL=0

# check <name> <block|allow> <filename> <content>
check() {
  local name="$1" expect="$2" fname="$3" content="$4"
  local d got
  d=$(mktemp -d)
  got=$(
    cd "$d" || exit
    git init -q
    cp "$HOOK" .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
    printf '%s\n' "$content" > "$fname"
    git add "$fname" >/dev/null 2>&1
    if git commit -qm t >/dev/null 2>&1; then echo allow; else echo block; fi
  )
  rm -rf "$d"
  if [ "$got" = "$expect" ]; then
    echo "  ✅ $name ($got)"; PASS=$((PASS + 1))
  else
    echo "  ❌ $name — expected $expect, got $got"; FAIL=$((FAIL + 1))
  fi
}

KEY="0x$(openssl rand -hex 32)"                     # a real 64-hex value
OAI="sk-$(openssl rand -hex 24)"                    # sk- + 48 hex

echo "LeakShield detection tests:"
# True positives — must BLOCK
check "real key in .env"          block .env       "PRIVATE_KEY=$KEY"
check "labeled key in code"       block leak.js    "const ETH_PRIVATE_KEY = \"$KEY\";"
check "AWS access key"            block aws.js     "const k = \"AKIAIOSFODNN7EXAMPLE\";"
check "OpenAI API key"            block ai.js      "const k = \"$OAI\";"
# False positives — must ALLOW (the bug this fix addresses)
check "bytes32, no secret context" allow gas.js    "const accountGasLimits = \"$KEY\";"
check "clean file"                allow ok.js      "export const x = 1;"

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
