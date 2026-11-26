#!/usr/bin/env bash
# Checks the `coredns` golden tree the way stormcentral builds it (#46):
# through deploy/build-golden.sh, into an empty OUT, and holds it to the tree
# stormcos's stage made (build-goldens.sh `if wanted coredns`, golden_from_dir).
#
#   deploy/check-image.sh        (sc-build 'deploy/check-image.sh')
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail() { echo "check-image: FAIL: $*" >&2; exit 1; }

# Refusals: another name, another architecture.
mkdir "$work/x"
rc=0; bash deploy/build-golden.sh stormcoredns "$work/x" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "name 'stormcoredns' exited $rc, want 2"
rc=0; GOLDEN_ARCH=aarch64 bash deploy/build-golden.sh coredns "$work/x" >/dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || fail "GOLDEN_ARCH=aarch64 exited $rc, want 2"
[ -z "$(ls -A "$work/x")" ] || fail "a refused build wrote into OUT"
echo "ok: other names and architectures refused (exit 2), nothing written"

out="$work/tree"; mkdir "$out"
bash deploy/build-golden.sh coredns "$out"

# Exactly the stage's entries, types and modes.
got=$(cd "$out" && find . -mindepth 1 -printf '%P %y %m %l\n' | sed 's/ *$//' | LC_ALL=C sort)
want=$(LC_ALL=C sort <<'T'
coredns l 777 stormcoredns
dev d 755
etc d 755
etc/coredns d 755
proc d 755
stormcoredns f 755
sys d 755
tmp d 1777
T
)
[ "$got" = "$want" ] || { diff <(echo "$want") <(echo "$got") >&2 || true; fail "tree differs from the stage's"; }
echo "ok: tree is the stage's 8 entries (stormcoredns 0755, coredns -> stormcoredns, etc/coredns, proc sys dev, tmp 1777)"

file "$out/stormcoredns" | grep -Eq 'x86-64.*(static-pie linked|statically linked)' || fail "not static x86-64: $(file "$out/stormcoredns")"
echo "ok: $(file -b "$out/stormcoredns" | cut -d, -f1-2), $(stat -c %s "$out/stormcoredns") bytes"

version=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
v=$("$out/coredns" -version)
case "$v" in "stormcoredns-$version "*) ;; *) fail "/coredns -version: '$v'" ;; esac
echo "ok: /coredns -version: $v"
"$out/coredns" -plugins | grep -q 'kubernetes' || fail "-plugins lists no kubernetes"
echo "ok: -plugins lists kubernetes"

# Serves: whoami on a loopback port, asked over UDP with a raw query for
# whoami.example. A (no dig on a build VM).
port=$((20000 + RANDOM % 20000))
printf '.:%s {\n    bind 127.0.0.1\n    whoami\n}\n' "$port" > "$work/Corefile"
"$out/coredns" -conf "$work/Corefile" > "$work/coredns.log" 2>&1 & pid=$!
trap 'kill $pid 2>/dev/null || true; rm -rf "$work"' EXIT
cat > "$work/ask.py" <<'PY'
import socket, sys
q = bytes.fromhex("1234010000010000000000000677686f616d69076578616d706c650000010001")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
s.sendto(q, ("127.0.0.1", int(sys.argv[1])))
r = s.recv(512)
# whoami answers as CoreDNS's does: the client's A and _udp SRV in the
# additional section, none in the answer section.
assert r[:2] == b"\x12\x34" and r[3] & 0x0f == 0 and int.from_bytes(r[10:12], "big") == 2, r.hex()
assert b"\x00\x01\x00\x01" in r[32:] and b"\x7f\x00\x00\x01" in r and b"\x04_udp" in r, r.hex()
print(f"NOERROR, additional A 127.0.0.1 + _udp SRV, {len(r)} bytes")
PY
ans=""
command -v python3 >/dev/null || fail "no python3 on this machine for the UDP query"
for _ in $(seq 100); do
    ans=$(python3 "$work/ask.py" "$port" 2>"$work/ask.err") && break
    ans=""
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
done
if [ -z "$ans" ]; then
    echo "--- Corefile"; cat "$work/Corefile"
    echo "--- coredns log"; cat "$work/coredns.log"
    echo "--- last query error"; cat "$work/ask.err"
    kill -0 "$pid" 2>/dev/null && echo "(coredns still running)" || echo "(coredns exited)"
    fail "no answer from /coredns on 127.0.0.1:$port"
fi
echo "ok: /coredns answers whoami over UDP: $ans"

# Same commit, same bytes: a second build into a fresh OUT.
out2="$work/tree2"; mkdir "$out2"
bash deploy/build-golden.sh coredns "$out2" >/dev/null
[ "$(sha256sum < "$out/stormcoredns")" = "$(sha256sum < "$out2/stormcoredns")" ] || fail "a second build gave other bytes"
echo "ok: a second build gives the same bytes ($(sha256sum < "$out/stormcoredns" | cut -c1-16))"
echo "check-image: PASS"
