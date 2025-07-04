from mpit_logger import printl
import json
from rich.progress import Progress
from rich.console import Console
from rich.table import Table

OUTPUT_FILE = "patterns/new_instruction_prompt_leaking.json"

# Input files
OBJECT_FIRST_PART_FILE =  "patterns/prompt_leaking_seeds/object_first_part.json"
OBJECT_SECOND_PART_FILE = "patterns/prompt_leaking_seeds/object_second_part.json"
REPEAT_VERB_FILE =        "patterns/prompt_leaking_seeds/repeat_verb.json"
REPEAT_REASON_FILE =      "patterns/prompt_leaking_seeds/repeat_reason.json"
CONVERT_VERB_FILE =       "patterns/prompt_leaking_seeds/convert_verb.json"
CONVERT_TARGET_FILE =     "patterns/prompt_leaking_seeds/convert_target.json"
CONVERT_REASON_FILE =     "patterns/prompt_leaking_seeds/convert_reason.json"

# Load input files
printl("Loading input files...", "info")
with open(OBJECT_FIRST_PART_FILE, 'r', encoding='utf-8') as file:
  first_part = json.load(file)
with open(OBJECT_SECOND_PART_FILE, 'r', encoding='utf-8') as file:
  second_part = json.load(file)
with open(REPEAT_VERB_FILE, 'r', encoding='utf-8') as file:
  repeat_verbs = json.load(file)
with open(REPEAT_REASON_FILE, 'r', encoding='utf-8') as file:
  repeat_reasons = json.load(file)
with open(CONVERT_VERB_FILE, 'r', encoding='utf-8') as file:
  convert_verbs = json.load(file)
with open(CONVERT_TARGET_FILE, 'r', encoding='utf-8') as file:
  convert_targets = json.load(file)
with open(CONVERT_REASON_FILE, 'r', encoding='utf-8') as file:
  convert_reasons = json.load(file)


# Combine first and second parts of objects (C1 + C2)
objects=[]
with Progress() as progress:
  task = progress.add_task("[green]Processing C Object...", total=len(first_part))
  for first in first_part:
    for second in second_part:
      objects.append({
        "name": f"{first['name']}~{second['name']}",
        "value": first["value"] + second["value"],
        "score": first["score"] + second["score"]
      })
      progress.advance(task)


# Generate repeat patterns (A1 + A2)
prompt_leaking_patterns = []

with Progress() as progress:
  task = progress.add_task("[green]Processing repeat patterns...", total=len(repeat_verbs))

  for verb in repeat_verbs:
    for obj in objects:
      pattern = (verb["value"].replace("{object}", obj["value"])).strip()
      if not pattern.endswith("."):
        pattern += "."
      item = {
        "name": f"{verb['name']}~{obj['name']}",
        "value": pattern,
        "score": verb["score"] + obj["score"],
        "verify": {
          "type": "prompt_leaking"
        },
        "reason": repeat_reasons
      }
      prompt_leaking_patterns.append(item)
    progress.advance(task)

# convert verb + object + target + reason + verify

with Progress() as progress:
  task = progress.add_task("[green]Processing convert patterns...", total=len(convert_verbs))

  for verb in convert_verbs:
    for obj in objects:
      for target in convert_targets:
        pattern = (verb["value"].replace("{object}", obj["value"]) + target["value"]).strip()
        if not pattern.endswith("."):
          pattern += "."
        item = {
          "name": f"{verb['name']}~{obj['name']}~{target['name']}",
          "value": pattern,
          "score": verb["score"] + obj["score"] + target["score"],
          "verify": {
            "type": "prompt_leaking"
          },
          "reason": convert_reasons
        }
        prompt_leaking_patterns.append(item)
    progress.advance(task)


# Count items
counts = {
  "A1 Repeat Verbs": len(repeat_verbs),
  "A2 Repeat Reasons": len(repeat_reasons),
  "B1 Convert Verbs": len(convert_verbs),
  "B2 Convert Targets": len(convert_targets),
  "B3 Convert Reasons": len(convert_reasons),
  "C1 Object First Part": len(first_part),
  "C2 Objection Second Part": len(second_part),
  "Total Patterns": len(prompt_leaking_patterns)
}

# Create and print Rich table
console = Console()
table = Table(title="Prompt Leaking Pattern Components")
table.add_column("Component", style="bold cyan")
table.add_column("Count", justify="right", style="green")

for key, count in counts.items():
  table.add_row(key, str(count))
console.print(table)

with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
    json.dump(prompt_leaking_patterns, file, indent=2, ensure_ascii=False)