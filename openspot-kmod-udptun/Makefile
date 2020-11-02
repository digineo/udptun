include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=openspot-kmod-udptun
PKG_VERSION:=0.1.0
PKG_RELEASE:=$(REVISION)

PKG_USE_MIPS16:=0

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel-defaults.mk

define KernelPackage/openspot-kmod-udptun
	SECTION:=udptun
	CATEGORY:=udptun
	TITLE:=OpenSpot udptun kernel module
	DEPENDS:=+IPV6:kmod-udptunnel6 +kmod-udptunnel4
	FILES:=$(PKG_BUILD_DIR)/udptun.$(LINUX_KMOD_SUFFIX)
	AUTOLOAD:=$(call AutoLoad,30,udptun)
endef

define Build/Compile
	$(MAKE) $(KERNEL_MAKEOPTS) M="$(PKG_BUILD_DIR)" modules
endef

$(eval $(call KernelPackage,openspot-kmod-udptun))
