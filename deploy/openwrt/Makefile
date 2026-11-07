include $(TOPDIR)/rules.mk

PKG_NAME:=ghostun
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/huihuimoe/ghostun.git
PKG_SOURCE_VERSION:=v$(PKG_VERSION)
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=huihuimoe
PKG_LICENSE:=AGPL-3.0-or-later
PKG_LICENSE_FILES:=LICENSE

PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/ghostun
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=L3 tunnel with FakeTCP and relay-compatible TCP transports
  URL:=https://github.com/huihuimoe/ghostun
  DEPENDS:=$(RUST_ARCH_DEPENDS) +kmod-tun +kmod-nft-core +kmod-nft-nat
endef

define Package/ghostun/description
  Ghostun is an L3 (IPv4 + IPv6) tunnel between two Linux hosts with two
  transport backends: FakeTCP (raw-socket crafted TCP headers) and standard
  kernel TCP (compatible with L4 TCP proxies and port forwarders).
endef

define Package/ghostun/conffiles
/etc/config/ghostun
endef

define Package/ghostun/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/ghostun $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/ghostun.init $(1)/etc/init.d/ghostun
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/ghostun.config $(1)/etc/config/ghostun
endef

$(eval $(call RustBinPackage,ghostun))
$(eval $(call BuildPackage,ghostun))
