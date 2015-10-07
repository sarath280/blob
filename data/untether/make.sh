gcc untether64.m -o untether -arch arm64 patchfinder_64.c  -isysroot "$(xcrun --show-sdk-path --sdk iphoneos)" -framework IOKit -framework Foundation -I/Users/qwertyoruiop/theos/include libarc.a -lz
ldid -Se.xml untether
