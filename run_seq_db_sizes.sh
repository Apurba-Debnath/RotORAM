#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Error: Please provide output filename as argument"
    exit 1
fi

OUTPUT_FILE="$1"

# Clear the output file if it exists
> $OUTPUT_FILE

total_tests=0
passed_tests=0
failed_tests=0

# Loop through desired values of database size exponent
for i in {15..17}
do
    echo "Running ./script_updated.sh 0 $i ..."
    echo "==================== Running with database size 2^$i ====================" >> $OUTPUT_FILE
    ./script_updated.sh 0 $i >> $OUTPUT_FILE 2>&1
    echo "" >> $OUTPUT_FILE
    echo "Completed run for database size 2^$i"

    total_tests=$((total_tests+1))

    if grep -q "Full row ORAM READ correct!" $OUTPUT_FILE && \
       grep -q "Full row ORAM WRITE correct!" "$OUTPUT_FILE"; then
        passed_tests=$((passed_tests + 1))
    else
        if grep -q "Full row ORAM READ incorrect" $OUTPUT_FILE && \
        grep -q "Full row ORAM WRITE incorrect" $OUTPUT_FILE; then
            failed_tests=$((failed_tests + 1))
        fi
    fi
done

echo "" >> $OUTPUT_FILE
echo "" >> $OUTPUT_FILE
echo "--------------------------Test Results Summary------------------------------" >> $OUTPUT_FILE

# Display final results
if [ $failed_tests -eq 0 ]; then
    echo "$passed_tests/$total_tests TESTS PASSED" >> $OUTPUT_FILE
else
    echo "$failed_tests/$total_tests TESTS FAILED" >> $OUTPUT_FILE
fi

echo "All runs completed! Output saved to $OUTPUT_FILE"

