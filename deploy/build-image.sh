#!/usr/bin/env bash
# The `coredns` golden — stormcoredns as the cluster DNS — built here, from
# this checkout, and nowhere else (#46, stormcentral#1836: "do repos, repos
# are not expensive"; stormcos's stage mode is retired).
#
#   deploy/build-image.sh coredns OUT
#
# stormcentral's component build runs it for the `coredns` component (kind
# `tree`: `deploy/build-golden.sh coredns OUT`, which execs this) in a
# checkout fetched at the exact commit, on a fresh build VM. OUT is copied
# into the sealed read-only golden `golden-coredns-<build>`, sized from the
# content, with `SBOM/crates.csv` added by the platform.
#
# Until 2026-11-26 stormcos's deploy/build-goldens.sh built it in stage mode
# (`if wanted coredns`, STORMCOREDNS_SRC), so every stormcos commit re-ran
# this compile only to find the output unchanged. That recipe is moved here
# unchanged:
#
#   cargo build --release --locked --target x86_64-unknown-linux-musl
#
# (the root package only — test/ is the test container, built by
# test/build.sh; `--profile dist` if Cargo.toml ever defines one: the stage's
# and stormcentral's rule.)
#
# The tree is exactly what the stage put in the golden (golden_from_dir):
#
#   stormcoredns         the server, static x86_64 musl, 0755
#   coredns -> stormcoredns
#                        the manifest runs /coredns (stormcos
#                        deploy/manifests/80-coredns.yaml), so it reads the
#                        same whichever implementation is in the image;
#                        /stormcoredns says which one a node got
#   etc/coredns/         empty: the Corefile comes from the ConfigMap
#   proc sys dev tmp     the mountpoints every runtime expects (tmp 1777)
#
# No upstream fallback, as in the stage: if stormcoredns does not build, the
# build fails and there is no `coredns` golden.
#
# x86_64 only, as in stage mode: any other GOLDEN_ARCH is refused.
set -euo pipefail
name=${1:?usage: deploy/build-image.sh coredns OUT}
out=${2:?usage: deploy/build-image.sh coredns OUT}
[ "$name" = coredns ] || { echo "build-image: this repo builds only 'coredns', not '$name'" >&2; exit 2; }
arch=${GOLDEN_ARCH:-x86_64}
[ "$arch" = x86_64 ] || { echo "build-image: coredns is built for x86_64 only (GOLDEN_ARCH=$arch)" >&2; exit 2; }
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
source "$HOME/.cargo/env" 2>/dev/null || true
TARGET=x86_64-unknown-linux-musl
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
commit=$(git rev-parse HEAD)
version=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "build-image: no package.version in Cargo.toml" >&2; exit 1; }
profile=release; grep -q '^\[profile\.dist\]' Cargo.toml && profile=dist

echo "==> cargo build --profile $profile --locked --target $TARGET -p stormcoredns ($commit)"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
    cargo build --profile "$profile" --locked --target "$TARGET" --quiet -p stormcoredns

bin="$CARGO_TARGET_DIR/$TARGET/$profile/stormcoredns"
[ -x "$bin" ] || { echo "build-image: cargo produced no $bin" >&2; exit 1; }
# Static: the golden has no loader and no libc; a glibc build would not start
# and the failure would say nothing useful.
if command -v file >/dev/null 2>&1; then
    file "$bin" | grep -Eq 'static-pie linked|statically linked' || { echo "build-image: stormcoredns is not static: $(file "$bin")" >&2; exit 1; }
fi
# The binary is this checkout at this version.
got=$("$bin" -version)
case "$got" in
    "stormcoredns-$version "*) ;;
    *) echo "build-image: stormcoredns says '$got', Cargo.toml says $version" >&2; exit 1 ;;
esac

chmod 0755 "$out"
install -m 0755 "$bin" "$out/stormcoredns"
# Read back what was copied: a short copy is never sealed (stormcentral#716).
[ "$(sha256sum < "$out/stormcoredns")" = "$(sha256sum < "$bin")" ] || { echo "build-image: stormcoredns does not read back as built" >&2; exit 1; }
ln -sfn stormcoredns "$out/coredns"
mkdir -p "$out/etc/coredns" "$out/proc" "$out/sys" "$out/dev" "$out/tmp"
chmod 0755 "$out/etc" "$out/etc/coredns" "$out/proc" "$out/sys" "$out/dev"
chmod 1777 "$out/tmp"

echo "==> coredns golden tree in $out: stormcoredns $version at $commit"
(cd "$out" && find . -mindepth 1 -printf '%M %8s %P %l\n' | LC_ALL=C sort -k3)
(cd "$out" && sha256sum stormcoredns)
