#!/bin/bash

# Configuration
NUM_TIMES=2
TEMP_DIR="$(pwd)/temp_runs_avg_calc_oram"
BASE_OUTPUT_NAME="terminal_output_run_oram"

# Create temp directory if it doesn't exist
mkdir -p "$TEMP_DIR"

echo "=========================================="
echo "Running script $NUM_TIMES times"
echo "Output directory: $TEMP_DIR"
echo "=========================================="
echo ""

# Loop to run the script NUM_TIMES
for run in $(seq 1 $NUM_TIMES)
do
    echo "=========================================="
    echo "Starting Run $run/$NUM_TIMES"
    echo "=========================================="
    
    OUTPUT_FILE="$TEMP_DIR/${BASE_OUTPUT_NAME}_${run}.txt"
    
    echo "Output will be saved to: $OUTPUT_FILE"
    
    # Run the original script
    ./run_seq_db_sizes.sh "$OUTPUT_FILE"
    
    echo ""
    echo "  Completed Run $run/$NUM_TIMES"
    echo "  Output saved to: $OUTPUT_FILE"
    echo ""
    
done

echo "=========================================="
echo "All $NUM_TIMES runs completed!"
echo "=========================================="
echo ""
echo "Output files in $TEMP_DIR:"
ls -lh "$TEMP_DIR"/${BASE_OUTPUT_NAME}_*.txt

echo ""
echo "To extract and average the data, run:"
echo "python3 avg_run_data_extract_script.py '$TEMP_DIR/${BASE_OUTPUT_NAME}_*.txt'"

