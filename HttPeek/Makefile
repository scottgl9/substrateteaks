ARCHS := armv7

include /opt/theos/makefiles/common.mk

TWEAK_NAME = HttPeek
HttPeek_FILES = HttPeek/HttPeek.m HttPeek/LogData.mm

#mgtest_LIBRARIES = MobileGestalt

HttPeek_FRAMEWORKS = UIKit Foundation CoreFoundation Security

# Build as a Substrate Tweak
HttPeek_CFLAGS=-DSUBSTRATE_BUILD

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk

cleanall: clean
	rm -rfv packages/*

#package-install: cleanall all package
#	mv packages/com.scottgl.mgtest_0.10-*+debug_iphoneos-arm.deb packages/com.scottgl.mgtest.deb
#	scp packages/com.scottgl.mgtest.deb root@10.79.0.5:/var/root

after-install::
	# Respring the device
	install.exec "killall -9 SpringBoard"
