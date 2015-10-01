SCRIPTPATH=`dirname $0`
cd $SCRIPTPATH
rm magic.dylib
gcc main.m -o main -framework Foundation libxnuexp.m -m32 -isysroot "$(xcrun --show-sdk-path)" && ./main && echo "Generated exploit dylib"
