#!/bin/bash
# echo "Hope This program will output correct answer ...finger cross";

# Check if the input is a valid number
if [[ ! "$1" =~ ^-?[0-9]+$ ]]; then
    echo "Invalid input. Please enter a valid number."
    exit 1
fi

# Accept power of 2 as parameter
if [ "$2" ]; then
    ITEM_COUNT=$((2**$2))
else
    ITEM_COUNT=32768  # default
fi

# run only
if [ "$1" == 0 ]; then 
	cd target/release/
	# ./panacea --mode 0
    ./panacea --mode 0 --item-count $ITEM_COUNT
	cd ../..

#Compile/build only
elif [ "$1" == 1 ]; then
	cd target/release/
	cargo clean
	cd ../..
	cargo +nightly build --release

# compile/build and run
else
	cd target/release/
	cargo clean
	cd ../..
	cargo +nightly build --release
	cd target/release/
    # ./panacea --mode 0
	# ./panacea --mode 0 --item-count 32768 --polynomial-size 2048
    ./panacea --mode 0 --item-count $ITEM_COUNT

fi
