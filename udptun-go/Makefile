include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=udptun-go
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(REVISION)

PKG_BUILD_DEPENDS:=golang/host

PKG_USE_MIPS16:=0

GO_PKG:=main
# GO_PKG_BUILD_PKG:=udptun/cmd/udptun

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/package-defaults.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/udptun-go
	SECTION:=udptun
	CATEGORY:=udptun
	TITLE:=udptun configuration tool
	DEPENDS:=$(GO_ARCH_DEPENDS) \
		+kmod-openspot-kmod-udptun
endef

define Package/udptun-go/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(CP) ./files/* $(1)/
	$(LN) /usr/bin/main $(1)/usr/bin/udptun
endef

$(eval $(call GoBinPackage,udptun-go))
$(eval $(call BuildPackage,udptun-go))
