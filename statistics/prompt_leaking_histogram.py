import json
import pandas as pd
import matplotlib.pyplot as plt

# Load JSON file
with open("../patterns/new_instruction_prompt_leaking.json", "r", encoding="utf-8") as f:
  data = json.load(f)

# Prepare data
rows = []
for item in data:
  value = item["value"]
  score_list = item["score"]
  avg_score = sum(score_list) / len(score_list) if score_list else 0
  rows.append({"value": value, "average_score": avg_score})

# Create DataFrame and sort
df = pd.DataFrame(rows)
df = df.sort_values(by="average_score", ascending=False)

# Plot histogram
plt.figure(figsize=(8, 6))
plt.hist(df["average_score"], bins=10, edgecolor="black")
plt.title("Distribution of Average Scores")
plt.xlabel("Average Score")
plt.ylabel("Number of Patterns")
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.show()
