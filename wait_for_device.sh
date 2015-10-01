#!/bin/sh
echo "Waiting for device..."
while ! (./bin/afcclient deviceinfo | grep FSTotalBytes >/dev/null); do sleep 5; done 2>/dev/null

