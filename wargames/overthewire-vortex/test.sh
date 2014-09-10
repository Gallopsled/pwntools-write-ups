#!/bin/bash

for level in $(seq 0 13);
do
    cd level$level
    echo python $PWD/win.py SILENT PASSWORD=$PASS
    PASS="$(python win.py SILENT PASSWORD="$PASS")"
    echo "Password: $PASS"
    cd ..
done

echo $PASS
