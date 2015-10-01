#!/bin/sh
SCRIPTPATH=`dirname $0`
cd $SCRIPTPATH

function abort() {
echo "Error. Exiting..."
exit 254;
}

echo "Setting up environment..."
./bin/afcclient put ./data/WWDC_Info_TOC.plist /yalu.plist | grep Uploaded || abort
echo
printf "Installing app & swapping binaries..."
./bin/mobiledevice install_app ./data/WWDC-TOCTOU.ipa || abort
echo
echo "Waiting.."
sleep 5
./bin/afcclient put ./data/WWDC_Info_TOU.plist /yalu.plist | grep Uploaded || abort
echo
