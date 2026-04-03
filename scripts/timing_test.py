# timing_test.py
# Script to measure and compare response times for valid and invalid usernames
# against the WebAuthn authentication options endpoint.
# Used to check for timing side-channels in the backend implementation.
import requests
import time
import random
import string
import statistics
import json

URL = "http://localhost:8080/api/webauthn/authenticate/options"
VALID_USERNAMES = ["test1", "test2", "test3", "test4", "test5", "test6", "test7", "test8", "test123"]
N_REQUESTS = 1000

def random_username(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def measure_requests(usernames, label):
    times = []
    for i in range(N_REQUESTS):
        username = random.choice(usernames)
        start = time.time()
        try:
            response = requests.post(URL, params={"username": username})
        except Exception as e:
            print(f"Request failed: {e}")
            continue
        elapsed = (time.time() - start) * 1000  # ms
        times.append(elapsed)
        if (i+1) % 100 == 0:
            print(f"{label}: {i+1} requests sent")
    print(f"\n{label} - Latency stats (ms):")
    print(f"  Mean: {statistics.mean(times):.2f}")
    print(f"  Median: {statistics.median(times):.2f}")
    print(f"  Min: {min(times):.2f}")
    print(f"  Max: {max(times):.2f}")
    print(f"  Stddev: {statistics.stdev(times):.2f}")
    return times

if __name__ == "__main__":
    print("Testing VALID usernames...")
    valid_times = measure_requests(VALID_USERNAMES, "VALID")
    print("\nTesting INVALID usernames...")
    invalid_usernames = [random_username() for _ in range(N_REQUESTS)]
    invalid_times = measure_requests(invalid_usernames, "INVALID")

    with open("valid_times.json", "w") as f:
        json.dump(valid_times, f)
    with open("invalid_times.json", "w") as f:
        json.dump(invalid_times, f)
