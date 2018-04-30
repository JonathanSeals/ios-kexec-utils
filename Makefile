all:
	xcrun -sdk iphoneos clang kloader.c -arch armv7 -arch arm64 -framework IOKit -framework CoreFoundation -Wall -miphoneos-version-min=4.0 -o kloader
	ldid -Stfp0.plist kloader
