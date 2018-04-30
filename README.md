# kloader (ios-kexec-utils)

## Features

* made by winocm and improved by axi0mX

* armv7 support for iOS 4.0-9.3.5 (requires a jailbreak with tfp0 kernel patch)

* arm64 support for iOS 7.0-8.4.1 (requires a jailbreak with tfp0 kernel patch and patched LLB/iBoot/iBSS/iBEC)

* will automatically wake up device after 2 seconds (no button press required, should work 99.9% of the time)

Use the provided binary if you do not need to change kloader source code.

Please report issues on GitHub and I will do my best to fix them.


## Dependencies

These dependencies are only needed if you wish to compile kloader.

* Xcode

Latest version will work, but the following 2 files must be copied from a DMG of an older version of Xcode. I used Xcode_6.4.dmg.

```
Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/libgcc_s.1.dylib
Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/crt1.3.1.o
```

* ldid

Homebrew can be used to install ldid on macOS.

```
brew install ldid
```
