#!/bin/sh
ddi="$(find /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/|grep 8.4|grep .dmg'$'|head -1)"
echo "Mounting DDI..."
./bin/ideviceimagemounter "$ddi"  >/dev/null || echo "Couldn't mount DDI. Not an issue if Xcode's running, an issue if it isn't."
