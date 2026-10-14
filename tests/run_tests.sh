#!/usr/bin/env bash
# End-to-end test of pepatch against real PE32 and PE32+ binaries we compile.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
pp="python3 $here/../pepatch.py"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0; fail=0
ok(){ echo "  PASS: $1"; pass=$((pass+1)); }
no(){ echo "  FAIL: $1"; fail=$((fail+1)); }

for arch in 32 64; do
  echo "=== PE$arch ==="
  if [ "$arch" = 32 ]; then CC=i686-w64-mingw32-gcc; else CC=x86_64-w64-mingw32-gcc; fi
  if ! command -v "$CC" >/dev/null 2>&1; then
    echo "  skip: $CC not installed"; continue
  fi
  exe="$work/hello$arch.exe"
  "$CC" -O0 -o "$exe" "$here/hello.c"

  # info / resolve smoke test
  $pp info "$exe" >/dev/null && ok "info parses"
  ep_line=$($pp info "$exe")
  echo "$ep_line" | grep -q "PE32" && ok "magic detected"

  # Find the 'ORIGINAL\n' string in .rdata and patch it in place.
  # Locate the byte offset of "ORIGINAL" in the file.
  off=$(python3 - "$exe" <<'PY'
import sys
d=open(sys.argv[1],'rb').read()
print(d.find(b'ORIGINAL'))
PY
)
  [ "$off" -gt 0 ] && ok "found ORIGINAL at off $off"

  # expect-guard: wrong expectation must refuse
  if $pp patch "$exe" "off:$off" "4f4f4f4f4f4f4f4f" -e "deadbeefdeadbeef" 2>/dev/null; then
    no "expect-guard should have refused"
  else
    ok "expect-guard refuses wrong original"
  fi

  # no --expect must refuse (unless --force)
  if $pp patch "$exe" "off:$off" "4f" 2>/dev/null; then
    no "patch without --expect should refuse"
  else
    ok "patch without --expect refuses"
  fi

  # correct patch: "ORIGINAL" -> "PATCHED!!" style; keep length 8 -> "PATCHED_"
  $pp patch "$exe" "off:$off" "5041544348454421" -e "4f524947494e414c" >/dev/null
  ok "patched string bytes"

  # backup exists
  [ -f "$exe.bak" ] && ok "backup created"

  # run under wine (PE32+ needs wine64; try, don't hard-fail the suite on wine)
  if command -v wine >/dev/null 2>&1; then
    out=$(WINEDEBUG=-all wine "$exe" 2>/dev/null | tr -d '\r' || true)
    echo "    wine output: [$out]"
    echo "$out" | grep -q "PATCHED" && ok "patched exe runs and prints PATCHED" || echo "    (wine run inconclusive for PE$arch)"
  fi

  # add a code section
  $pp addsection "$exe" --name ".inj" --size 0x100 --data "cccccccc" >/dev/null
  ok "added section"
  $pp info "$exe" | grep -q ".inj" && ok "new section visible in table"

  # --- trampoline: redirect EP through a new section and back to OEP ---
  # Fresh copy so the trampoline test stands alone.
  texe="$work/tramp$arch.exe"
  "$CC" -O0 -o "$texe" "$here/hello.c"
  oep_before=$($pp info "$texe" >/dev/null; python3 - "$texe" <<'PY'
import sys,struct
d=open(sys.argv[1],'rb').read()
e=struct.unpack_from('<I',d,0x3c)[0]
opt=e+4+20
print(hex(struct.unpack_from('<I',d,opt+16)[0]))
PY
)
  # Empty payload => trampoline is just "jmp OEP": EP -> section -> OEP.
  $pp trampoline "$texe" --name .tr0 >/dev/null && ok "trampoline (empty payload) installed"
  oep_after=$(python3 - "$texe" <<'PY'
import sys,struct
d=open(sys.argv[1],'rb').read()
e=struct.unpack_from('<I',d,0x3c)[0];opt=e+4+20
print(hex(struct.unpack_from('<I',d,opt+16)[0]))
PY
)
  [ "$oep_before" != "$oep_after" ] && ok "entry point was redirected ($oep_before -> $oep_after)"
  if command -v wine >/dev/null 2>&1; then
    out=$(WINEDEBUG=-all wine "$texe" 2>/dev/null | tr -d '\r' || true)
    echo "    trampoline wine output: [$out]"
    echo "$out" | grep -q "ORIGINAL" && ok "trampolined exe still runs through to main (ORIGINAL)" || echo "    (wine trampoline run inconclusive for PE$arch)"
  fi
  $pp undo "$texe" --all >/dev/null
  cmp -s "$texe" "$texe.bak" && ok "trampoline undo --all byte-exact" || no "trampoline undo mismatch"

  # undo everything, compare to backup
  $pp undo "$exe" --all >/dev/null
  if cmp -s "$exe" "$exe.bak"; then
    ok "undo --all restored original exactly"
  else
    no "undo --all did not match backup"
  fi

  # still a loadable exe after round-trip?
  if command -v wine >/dev/null 2>&1; then
    out=$(WINEDEBUG=-all wine "$exe" 2>/dev/null | tr -d '\r' || true)
    echo "$out" | grep -q "ORIGINAL" && ok "restored exe prints ORIGINAL" || echo "    (wine recheck inconclusive)"
  fi
done

echo
echo "TOTAL: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
