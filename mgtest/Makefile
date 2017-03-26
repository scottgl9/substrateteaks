ARCHS := armv7

# arm64

include /opt/theos/makefiles/common.mk

TWEAK_NAME = mgtest
mgtest_FILES = mgtest/MGTest.m
mgtest_LIBRARIES = MobileGestalt

mgtest_FRAMEWORKS = UIKit Foundation CoreFoundation Security
#mgtest_FRAMEWORKS = Foundation CoreFoundation Security

# Build as a Substrate Tweak
mgtest_CFLAGS=-DSUBSTRATE_BUILD

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk

cleanall: clean
	rm -rfv packages/*

package-install: cleanall all package
	mv packages/com.scottgl.mgtest_0.10-*+debug_iphoneos-arm.deb packages/com.scottgl.mgtest.deb
	scp packages/com.scottgl.mgtest.deb root@10.79.0.5:/var/root

after-install::
	# Respring the device
	install.exec "killall -9 SpringBoard"
