include $(TOPDIR)/rules.mk

PKG_NAME:=lan-service-gateway
PKG_VERSION:=0.1.0
PKG_RELEASE:=6
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/lan-service-gateway
  SECTION:=net
  CATEGORY:=Network
  TITLE:=LocalSend discovery gateway for routed LANs
  DEPENDS:=+firewall4
endef

define Package/lan-service-gateway/description
  Discovers verified downstream LocalSend peers, publishes them upstream,
  and installs narrow firewall4 mappings. Optionally forwards ports for
  one configured Sunshine host.
endef

define Package/lan-service-gateway/conffiles
/etc/config/lan-service-gateway
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./files/lan-service-gateway.bin $(PKG_BUILD_DIR)/lan-service-gateway
endef

define Build/Compile
endef

define Package/lan-service-gateway/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/etc/config $(1)/etc/init.d $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lan-service-gateway $(1)/usr/sbin/lan-service-gateway
	$(INSTALL_CONF) ./files/lan-service-gateway.config $(1)/etc/config/lan-service-gateway
	$(INSTALL_BIN) ./files/lan-service-gateway.init $(1)/etc/init.d/lan-service-gateway
	$(INSTALL_BIN) ./files/lan-service-gateway.hotplug $(1)/etc/hotplug.d/iface/90-lan-service-gateway
endef

$(eval $(call BuildPackage,lan-service-gateway))
