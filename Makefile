CLANG=/mnt/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi16-clang

all: build

build:
	@echo "  CAT   src/*.c"
	@cat src/stub.c src/log-push.c src/func.c > src/all.c
	@echo "  CC    src/*.c"
	@$(CLANG) -c -I src -O2 -fPIC src/all.c -o libssl.o
	@echo "  LD    libssl.so"
	@$(CLANG) -fPIC -fPIE -shared -o libssl.so libssl.o -Wl,--hash-style=sysv -ldl

install:
	@adb push libssl.so libSSL.so /data/local/tmp/
	@adb shell 'su -c mount -o remount,rw /system'
	@adb shell 'su -c cp -v /data/local/tmp/libssl.so /system/lib/libssl.so'
	@adb shell 'su -c cp -v /data/local/tmp/libSSL.so /system/lib/libSSL.so'
	@adb shell 'su -c mount -o remount,ro /system'
	@adb shell 'sync'

restore:
	@adb push sys/libssl.so /data/local/tmp/
	@adb shell 'su -c mount -o remount,rw /system'
	@adb shell 'su -c cp -v /data/local/tmp/libssl.so /system/lib/libssl.so'
	@adb shell 'su -c mount -o remount,ro /system'
	@adb shell 'sync'

recovery:
	@adb push orig/* /tmp/
	@adb shell 'mkdir /tmp/system'
	@adb shell 'mount /dev/block/platform/*/by-name/SYSTEM /tmp/system'
	@adb shell 'cat /tmp/libssl.so.orig > /tmp/system/lib/libssl.so'
	@adb shell 'chcon u:object_r:system_library_file:s0 /tmp/system/lib/libssl.so'
	@adb shell 'chmod 644 /tmp/system/lib/libssl.so
	@adb shell 'chown root /tmp/system/lib/libssl.so
	@adb shell 'chgrp root /tmp/system/lib/libssl.so
	@adb shell ''

reset:
	@adb shell 'su -c rm /data/data/package_of_your_app/files/log/*'

pull:
	@adb shell 'su -c rm -rf /sdcard/log'
	@adb shell 'rm -f /sdcard/log; su -c cp -r /data/data/package_of_your_app/files/log /sdcard/log'
	@sh -c 'cd /tmp; rm -rf z; mkdir -p z; rm -f log; adb pull /sdcard/log log; h2split log z'

clean:
	@rm -f *.o *.so
