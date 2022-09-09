
create_data() {
    FILE_NAME=$1
    SIZE_KB=$2

    rm -f $FILE_NAME

    for (( i=0; i<$SIZE_KB; i++ ))
    do
        cat $TEST_SRC_DIR/test_data.bin >> $FILE_NAME
    done
}
