import json
import pandas as pd

# Load the JSON file
with open("../patterns/new_instruction_prompt_leaking.json", "r", encoding="utf-8") as f:
  data = json.load(f)

# Create a list of rows with 'value' and average of 'score'
rows = []
for item in data:
  value = item["value"]
  score_list = item["score"]
  avg_score = sum(score_list) / len(score_list) if score_list else 0
  rows.append({"value": value, "average_score": avg_score})

# Create a DataFrame and sort by average_score descending
df = pd.DataFrame(rows)
df = df.sort_values(by="average_score", ascending=False)

# Show the table
print(df.to_markdown(index=False))  # Or use print(df) if tabulate is not installed
