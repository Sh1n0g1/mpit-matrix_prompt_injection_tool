import numpy as np

def kmeans_1d(data, k=2, max_iters=100):
  data = np.array(data)
  centroids = np.array([data.min(), data.max()])

  for _ in range(max_iters):
    distances = np.abs(data[:, np.newaxis] - centroids[np.newaxis, :])
    labels = np.argmin(distances, axis=1)
    new_centroids = np.array([data[labels == i].mean() for i in range(k)])
    if np.allclose(centroids, new_centroids):
      break
    centroids = new_centroids

  return labels, np.sort(centroids)  # Sort centroids to keep order consistent

# Your data
numbers = [1,1,1,1,1,1,1,1,1,8,9,10]
labels, centroids = kmeans_1d(numbers)

# Calculate split point
split_number = centroids.mean()
print(f"Split number: {split_number:.2f}")

# Classification function
def classify(x, split_number):
  return "big" if x >= split_number else "small"

# Try new numbers
for test in [1, 4, 8, 10]:
  print(f"{test} → {classify(test, split_number)}")
