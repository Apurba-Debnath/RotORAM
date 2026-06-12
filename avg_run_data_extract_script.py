#!/usr/bin/env python3

import sys
import re
from statistics import mean
import glob


def extract_runtimes(filename):
    """Extract read/write runtimes into separate lists"""
    times_taken_read = []
    times_taken_write = []

    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found!")
        return [], []

    pattern_read = r'Time taken \(online\) - full row read:[^\d]*(\d+\.?\d*)\s*sec\.'
    pattern_write = r'Time taken \(online\) - full row write:[^\d]*(\d+\.?\d*)\s*sec\.'

    matches_read = re.findall(pattern_read, content, re.IGNORECASE)
    matches_write = re.findall(pattern_write, content, re.IGNORECASE)

    times_taken_read = [float(t) for t in matches_read]
    times_taken_write = [float(t) for t in matches_write]

    return times_taken_read, times_taken_write


def process_multiple_files(file_pattern):
    """Process multiple output files and compute averages"""

    files = glob.glob(file_pattern)

    if not files:
        print(f"Error: No files matching pattern '{file_pattern}' found!")
        sys.exit(1)

    print(f"Found {len(files)} files to process:")
    for f in files:
        print(f" - {f}")
    print()

    all_times_taken_read = []
    all_times_taken_write = []

    for filename in files:
        print(f"Processing {filename}...")
        read_temp, write_temp = extract_runtimes(filename)
        all_times_taken_read.append(read_temp)
        all_times_taken_write.append(write_temp)

    num_db_sizes = len(all_times_taken_read[0]) if all_times_taken_read else 0

    avg_time_read = []
    avg_time_write = []

    for i in range(num_db_sizes):
        read_vals = [run[i] for run in all_times_taken_read if i < len(run)]
        write_vals = [run[i] for run in all_times_taken_write if i < len(run)]

        if read_vals:
            avg_time_read.append(mean(read_vals))
        if write_vals:
            avg_time_write.append(mean(write_vals))

    return avg_time_read, avg_time_write


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 avg_run_data_extract_script.py '<file_pattern>'")
        print("Example: python3 avg_run_data_extract_script.py 'terminal_output_run*.txt'")
        sys.exit(1)

    file_pattern = sys.argv[1]

    avg_time_read, avg_time_write = process_multiple_files(file_pattern)

    print("\n" + "=" * 80)
    print("AVERAGED RESULTS")
    print("=" * 80)

    if avg_time_read:
        print(f"\navg_times_taken_read = [{', '.join(f'{t:.5f}' for t in avg_time_read)}]")
    else:
        print("\navg_times_taken_read = []")

    if avg_time_write:
        print(f"avg_times_taken_write = [{', '.join(f'{t:.5f}' for t in avg_time_write)}]")
    else:
        print("avg_times_taken_write = []")

    print(f"\nNumber of database sizes: {len(avg_time_read)}")
    print(f"Number of runs averaged: {len(glob.glob(file_pattern))}")
