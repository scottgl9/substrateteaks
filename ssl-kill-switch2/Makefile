ARCHS := armv7
#arm64

include /opt/theos/makefiles/common.mk

TWEAK_NAME = SSLKillSwitch2
SSLKillSwitch2_FILES = SSLKillSwitch/SSLKillSwitch.m SSLKillSwitch/HTTPParser.m

SSLKillSwitch2_FRAMEWORKS = Security

# Build as a Substrate Tweak
SSLKillSwitch2_CFLAGS=-DSUBSTRATE_BUILD

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk

doclean:
	rm -f packages/*.deb

doall: doclean clean all package
	sshpass -p alpine scp packages/*.deb root@10.79.0.5:/var/root
	sshpass -p alpine ssh root@10.79.0.5

after-install::
	# Respring the device
	install.exec "killall -9 SpringBoard"
