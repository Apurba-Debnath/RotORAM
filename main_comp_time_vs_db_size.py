import matplotlib.pyplot as plt
import numpy as np

# Database sizes: exponents of 2
powers = np.array([12, 14, 16, 18, 19, 20, 22])
# powers = np.arange(15, 33) # start index is inclusive, stop index is exclusive
database_sizes = 2 ** powers

# -----------------------------------------------------------------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------------------------------------------------------------
# results from Google compute machine
read_flag = 0
write_flag = 1

# read times
if read_flag == 1:
    times_taken_main_comp_rotpack = [3.55993, 3.57606, 3.57531, 3.58701, 3.57, 3.57120, 3.56759]
    times_taken_main_comp_panacea = [2.47, 9.53, 38.08, 147.92, 296.43]

# write times
if write_flag == 1:
    times_taken_main_comp_rotpack = [14.33614, 14.60402, 14.58231, 14.31898, 14.30, 14.22989, 14.26813]
    times_taken_main_comp_panacea = [1.01, 2.89, 11.04, 48.02, 94.83]

# -----------------------------------------------------------------------------------------------------------------------------------------------------
# -----------------------------------------------------------------------------------------------------------------------------------------------------


plt.figure(figsize=(10, 6))

if len(times_taken_main_comp_rotpack) > 0:
    plt.plot(database_sizes[:len(times_taken_main_comp_rotpack)], times_taken_main_comp_rotpack, marker='o', linewidth=2, markersize=8, color='g', label='RotORAM')

if len(times_taken_main_comp_panacea) > 0:
    plt.plot(database_sizes[:len(times_taken_main_comp_panacea)], times_taken_main_comp_panacea, marker='s', linewidth=2, markersize=8, color='r', label='Panacea')

plt.xlabel('Database Size', fontsize=18, fontweight='bold')
if read_flag == 1:
    plt.ylabel('Read time (seconds)', fontsize=18, fontweight='bold')
if write_flag == 1:
    plt.ylabel('Write time (seconds)', fontsize=18, fontweight='bold')
plt.grid(True, alpha=0.3, linestyle='--')
plt.legend(fontsize=18, loc='best')

plt.xscale('log', base=2)

from matplotlib.ticker import FuncFormatter
def format_func(value, tick_number):
    power = int(np.log2(value))
    return f'2^{power}'

plt.gca().xaxis.set_major_formatter(FuncFormatter(format_func))

plt.tight_layout()
if read_flag == 1:
    filename = 'read_times_rotoram_vs_panacea.png'
if write_flag == 1:
    filename = 'write_times_rotoram_vs_panacea.png'
plt.savefig(filename, dpi=300, bbox_inches='tight')
plt.show()

print(f"Graph saved as '{filename}'")
