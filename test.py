from itertools import product

def combine_patterns(*data_groups):
  result = []
  for combination in product(*data_groups):
    combined = {
      "name": "_".join(item["name"] for item in combination),
      "value": "".join(item["value"] for item in combination),
      "scores": [item["score"] for item in combination]
    }
    result.append(combined)
  return result


a_data = [
  {"name": "a-1", "value": "a1", "score": 10.0},
  {"name": "a-2", "value": "a2", "score": 5.0}
]

b_data = [
  {"name": "b-1", "value": "b1", "score": 10.0},
  {"name": "b-2", "value": "b2", "score": 5.0}
]

c_data = [
  {"name": "c-1", "value": "c1", "score": 8.0}
]

combined = combine_patterns(a_data, b_data, c_data)

for item in combined:
  print(item)