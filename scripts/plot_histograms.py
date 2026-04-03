import json
import matplotlib.pyplot as plt
import numpy as np

with open("valid_times.json") as f:
    valid = json.load(f)
with open("invalid_times.json") as f:
    invalid = json.load(f)

bins = 40
range_min = min(min(valid), min(invalid))
range_max = max(max(valid), max(invalid))
hist_range = (range_min, range_max)

# Compute histogram data
valid_counts, bin_edges = np.histogram(valid, bins=bins, range=hist_range)
invalid_counts, _ = np.histogram(invalid, bins=bins, range=hist_range)

width = (bin_edges[1] - bin_edges[0]) / 3  # bar width

plt.bar(bin_edges[:-1], valid_counts, width=width, color="blue", alpha=0.7, label="Valid", align="edge")
plt.bar(bin_edges[:-1] + width, invalid_counts, width=width, color="red", alpha=0.7, label="Invalid", align="edge")

plt.xlabel("Latency (ms)")
plt.ylabel("Frequency")
plt.title("Latency Histogram: Valid vs Invalid Usernames (Side by Side)")
plt.legend()
plt.show()