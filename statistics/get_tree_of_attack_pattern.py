import json

def generate_tree(d: dict, indent: int = 0, key_name: str = "Root") -> str:
  lines = []
  prefix = "  " * indent + f"\"{key_name}\" → "
  
  if isinstance(d, dict):
    lines.append(f"{prefix}dict")
    for key, value in d.items():
      lines.append(generate_tree(value, indent + 1, key))
  elif isinstance(d, list):
    lines.append(f"{prefix}list[{len(d)}]")
    if d:
      sample = d[0]
      lines.append(generate_tree(sample, indent + 1, "[0]"))
  elif isinstance(d, str):
    lines.append(f"{prefix}str")
  elif isinstance(d, bool):
    lines.append(f"{prefix}bool")
  elif isinstance(d, int):
    lines.append(f"{prefix}int")
  elif isinstance(d, float):
    lines.append(f"{prefix}float")
  elif d is None:
    lines.append(f"{prefix}null")
  else:
    lines.append(f"{prefix}{type(d).__name__}")

  return "\n".join(lines)

if __name__ == "__main__":
  JSON_FILE = "../all_attack_patterns.json"
  OUTPUT_FILE = "tree_structure.txt"
  
  with open(JSON_FILE, 'r', encoding='utf-8') as file:
    data = json.load(file)

  tree_str = f"Generating tree structure for {JSON_FILE}...\n"
  tree_str += generate_tree(data)
  tree_str += "\nTree structure generation complete.\n"

  with open(OUTPUT_FILE, 'w', encoding='utf-8') as out:
    out.write(tree_str)
