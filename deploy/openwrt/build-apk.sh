#!/bin/sh
# Build an OpenWrt 25.10+ (.apk) package from a compiled ghostun binary.
#
# Usage:
#   ./deploy/openwrt/build-apk.sh <binary_path> <version> <openwrt_arch> <output_dir> [pkg_release]
#
# Example:
#   ./deploy/openwrt/build-apk.sh dist/ghostun-linux-amd64 0.2.0 x86_64 dist 1

set -eu

if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
	echo "Usage: $0 <binary_path> <version> <openwrt_arch> <output_dir> [pkg_release]" >&2
	exit 1
fi

BIN_PATH="$1"
RAW_VERSION="$2"
ARCH="$3"
OUT_DIR="$4"
PKG_RELEASE="${5:-1}"

SCRIPT_DIR="$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)"
INIT_PATH="$SCRIPT_DIR/files/ghostun.init"
CONF_PATH="$SCRIPT_DIR/files/ghostun.config"

if [ ! -f "$BIN_PATH" ]; then
	echo "error: binary not found at $BIN_PATH" >&2
	exit 1
fi

if ! command -v apk >/dev/null 2>&1; then
	echo "error: 'apk' (apk-tools v3 with mkpkg support) is required" >&2
	exit 1
fi

# Sanitize version for APK v3 version rules:
# - Strip leading 'v'
# - Convert semver pre-release '-rc.1' / '-alpha.1' / '-beta.1' into '_rc1' / '_alpha1' / '_beta1'
# - Replace remaining '-' with '_'
SANITIZED_VER="$(printf '%s' "$RAW_VERSION" | sed -E \
	-e 's/^v//' \
	-e 's/-rc\.?([0-9]+)/_rc\1/g' \
	-e 's/-alpha\.?([0-9]+)/_alpha\1/g' \
	-e 's/-beta\.?([0-9]+)/_beta\1/g' \
	-e 's/-pre\.?([0-9]+)/_pre\1/g' \
	-e 's/-/_/g')"

FULL_VERSION="${SANITIZED_VER}-r${PKG_RELEASE}"
PKG_NAME="ghostun"
OUT_FILE="${OUT_DIR}/${PKG_NAME}_${FULL_VERSION}_${ARCH}.apk"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

IDIR="$WORK_DIR/root"
ADIR="$WORK_DIR/scripts"
mkdir -p \
	"$IDIR/usr/bin" \
	"$IDIR/etc/init.d" \
	"$IDIR/etc/config" \
	"$IDIR/lib/apk/packages" \
	"$ADIR"

install -m 0755 "$BIN_PATH" "$IDIR/usr/bin/ghostun"
install -m 0755 "$INIT_PATH" "$IDIR/etc/init.d/ghostun"
install -m 0600 "$CONF_PATH" "$IDIR/etc/config/ghostun"

printf '/etc/config/ghostun\n' > "$IDIR/lib/apk/packages/${PKG_NAME}.conffiles"

# Generate package file list before writing conffiles_static, matching OpenWrt package-pack.mk
(
	cd "$IDIR"
	find . -mindepth 1 \( -type f -o -type l \) \
		! -path "./lib/apk/packages/${PKG_NAME}.conffiles" \
		! -path "./lib/apk/packages/${PKG_NAME}.list" \
		| sed 's/^\.//' | LC_ALL=C sort > "$IDIR/lib/apk/packages/${PKG_NAME}.list"
)

CONF_HASH="$(sha256sum "$IDIR/etc/config/ghostun" | awk '{print $1}')"
printf '/etc/config/ghostun %s\n' "$CONF_HASH" > "$IDIR/lib/apk/packages/${PKG_NAME}.conffiles_static"

cat > "$ADIR/post-install" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
[ -s /etc/uci-defaults/ghostun ] && /etc/uci-defaults/ghostun && rm -f /etc/uci-defaults/ghostun
exit 0
EOF

cat > "$ADIR/post-upgrade" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
if [ -x /etc/init.d/ghostun ] && /etc/init.d/ghostun enabled 2>/dev/null; then
	/etc/init.d/ghostun reload >/dev/null 2>&1 || true
fi
exit 0
EOF

cat > "$ADIR/pre-deinstall" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT:-}" ] && exit 0
if [ -x /etc/init.d/ghostun ]; then
	/etc/init.d/ghostun stop >/dev/null 2>&1 || true
	/etc/init.d/ghostun disable >/dev/null 2>&1 || true
fi
exit 0
EOF

chmod 0755 "$ADIR/post-install" "$ADIR/post-upgrade" "$ADIR/pre-deinstall"

mkdir -p "$OUT_DIR"

if [ "$(id -u)" -ne 0 ] && command -v fakeroot >/dev/null 2>&1; then
	FAKEROOT_CMD="fakeroot"
else
	FAKEROOT_CMD=""
fi

$FAKEROOT_CMD apk mkpkg \
	--info "name:${PKG_NAME}" \
	--info "version:${FULL_VERSION}" \
	--info "tags:openwrt:section=net" \
	--info "description:L3 tunnel with FakeTCP and relay-compatible TCP transports" \
	--info "arch:${ARCH}" \
	--info "license:AGPL-3.0-or-later" \
	--info "origin:feeds/base/net/ghostun" \
	--info "url:https://github.com/huihuimoe/ghostun" \
	--info "depends:libc kmod-tun kmod-nft-core kmod-nft-nat" \
	--script "post-install:$ADIR/post-install" \
	--script "post-upgrade:$ADIR/post-upgrade" \
	--script "pre-deinstall:$ADIR/pre-deinstall" \
	--files "$IDIR" \
	--output "$OUT_FILE"

echo "Built $OUT_FILE"
