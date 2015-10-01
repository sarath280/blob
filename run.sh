#!/bin/sh
function abort() {
exit 254;
}
if [ -d data/dyldmagic/ ]; then 
	./data/dyldmagic/make.sh; # compile dyldmagic if source is present
fi
./stage0.sh || abort
