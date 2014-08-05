for level in $(seq 0 13);
do
    cd level$level
    echo python $PWD/win.py PASSWORD=$PASS
    PASS=$((python win.py PASSWORD=$PASS >/dev/null) 2>&1)
    cd ..
done

echo $PASS