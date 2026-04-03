import json
import matplotlib.pyplot as plt
import numpy as np

with open("valid_times.json") as f:
    valid = json.load(f)
with open("invalid_times.json") as f:
    invalid = json.load(f)

means = [np.mean(valid), np.mean(invalid)]
labels = ["Valid", "Invalid"]
colors = ["blue", "red"]

plt.bar(labels, means, color=colors, alpha=0.7)
plt.ylabel("Mean Latency (ms)")
plt.title("Mean Latency: Valid vs Invalid Usernames")
plt.show()