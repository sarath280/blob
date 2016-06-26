gcc untether64.m -o untether -w -arch armv7 patchfinder_64.c  -isysroot "$(xcrun --show-sdk-path --sdk iphoneos)" -framework IOKit -framework Foundation libarc.a -lz
ldid -Se.xml untether
