#!/bin/sh
function abort() {
exit 254;
}
./stage0.sh || abort
