#!/bin/sh
SCRIPTPATH=`dirname $0`
cd $SCRIPTPATH

function abort() {
echo "Error. Exiting..." >&2
exit 254;
}

./wait_for_device.sh
rm -rf tmp
mkdir tmp
(
./bin/afcclient mkdir PhotoData/KimJongCracks
./bin/afcclient mkdir PhotoData/KimJongCracks/a
./bin/afcclient mkdir PhotoData/KimJongCracks/a/a
./bin/afcclient mkdir PhotoData/KimJongCracks/Library
./bin/afcclient mkdir PhotoData/KimJongCracks/Library/PrivateFrameworks
./bin/afcclient mkdir PhotoData/KimJongCracks/Library/PrivateFrameworks/GPUToolsCore.framework

./stage1.sh || exit

echo "Backing up..." >&2
./bin/idevicebackup2 backup tmp || abort
udid="$(ls tmp | head -1)"

mkdir tmp_ddi
hdiutil attach -quiet -nobrowse -mountpoint tmp_ddi data/DeveloperDiskImage.dmg
cp tmp_ddi/Applications/MobileReplayer.app/MobileReplayer tmp/MobileReplayer
cp tmp_ddi/Applications/MobileReplayer.app/Info.plist tmp/MobileReplayerInfo.plist
hdiutil detach tmp_ddi
rm -rf tmp_ddi

#./bin/patcharch
lipo tmp/MobileReplayer -thin armv7s -output ./tmp/MobileReplayer
./bin/mbdbtool tmp $udid CameraRollDomain put ./tmp/MobileReplayer Media/PhotoData/KimJongCracks/a/a/MobileReplayer || abort
)

echo "Restoring backup..."
(
./bin/idevicebackup2 restore tmp --system --reboot || abort
)>/dev/null
sleep 20
./wait_for_device.sh
echo
echo "Mounting DDI..."
./bin/ideviceimagemounter ./data/DeveloperDiskImage.dmg  >/dev/null || abort
