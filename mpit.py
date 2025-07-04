import csv
import sys
import json
import argparse
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
from mpit_ascii import print_logo
from mpit_logger import printl
from collections import defaultdict


def load_pattern_files()->dict:
  """
  Load pattern files from the patterns directory.
  """
  pattern_seeds = {}
  files=[
    "expected_input.json",
    "delimiter.json",
    "exploit.json",
    "new_instruction_prompt_leaking.json",
    "new_instruction_freellm.json",
    "new_instruction_mdi.json",
    "new_instruction_xss.json",
    "new_instruction_sqli.json",
    "new_instruction_rce.json"
  ]
  for file in files:
    with open(f"patterns/{file}", 'r', encoding='utf-8') as f:
      if file.startswith("new_instruction_"):
        patterns= json.load(f)
        for pattern in patterns:
          pattern["type"] = file[16:-5]  # Extract type from filename
        pattern_seeds.setdefault("new_instruction", []).extend(patterns)
      else:
        pattern_seeds[file[:-5]] = json.load(f)
  return pattern_seeds
  
def combine_patterns(pattern_seeds: dict) -> dict:
  """
  Combine patterns from different categories into a single dictionary.
  Parameters:
    pattern_seeds (dict): A dictionary containing lists of patterns from different categories.
  Returns:
    dict: A list of dictionaries, each representing a unique attack pattern.
    Each dictionary contains:
      - name: A string representing the name of the attack pattern.
      - value: A string representing the combined value of the attack pattern.
      - score: An integer representing the total score of the attack pattern.
      - verify: A dict indicating how the result should be verified.
  """

  total = (
    len(pattern_seeds["expected_input"]) *
    len(pattern_seeds["delimiter"]) *
    len(pattern_seeds["exploit"]) *
    len(pattern_seeds["new_instruction"]) 
  )
  printl("New instruction patterns count: " + str(len(pattern_seeds["new_instruction"])), "info")
  printl(f"Total combinations to generate: {total}", "info")
  attack_patterns =[]

  with Progress() as progress:
    task = progress.add_task("[green]Loading attack patterns...", total=total)
    for expected_input in pattern_seeds["expected_input"]:
      for delimiter in pattern_seeds["delimiter"]:
        for exploit in pattern_seeds["exploit"]:
          for new_instruction in pattern_seeds["new_instruction"]:
            for reason in new_instruction["reason"]:
              attack_patterns.append({
                "name": f"{expected_input['name']}_{delimiter['name']}_{exploit['name']}_{new_instruction['name']}_{reason['name']}",
                "value": f"{expected_input['value']}{delimiter['value']}{exploit['value']}{new_instruction['value']}{reason['value']}",
                "score": expected_input["score"] + delimiter["score"] + exploit["score"] + new_instruction["score"] + reason["score"],
                "verify": new_instruction["verify"],
                "type": new_instruction["type"]
              })
            progress.advance(task)
  return attack_patterns

def filter_patterns(attack_patterns: list, filter_criteria: dict) -> list:
  """
  Filter attack patterns based on the average score threshold and enabled attack types.

  Parameters:
    attack_patterns (list): A list of dictionaries representing attack patterns.
    filter_criteria (dict): Dictionary with:
      - "score_filter": minimum average score (float)
      - "type": list of enabled types (e.g., ["sqli", "xss"])

  Returns:
    list: A list of dictionaries that meet the criteria.
  """
  filtered = []

  with Progress() as progress:
    task = progress.add_task("[green]Filtering patterns...", total=len(attack_patterns))
    for pattern in attack_patterns:
      scores = pattern.get("score", [])
      pattern_type = pattern.get("type")

      if isinstance(scores, list) and scores:
        avg = sum(scores) / len(scores)
        if avg >= filter_criteria["score_filter"] and pattern_type in filter_criteria["type"]:
          filtered.append(pattern)
      progress.update(task, advance=1)

  return filtered

def get_statistics(patterns: list) -> dict:
  """
  Generate and display statistics of pattern types using Rich.

  Parameters:
    patterns (list): A list of dictionaries with a "type" or "verify.type".

  Returns:
    dict: A dictionary with type as key and count as value.
  """
  stats = defaultdict(int)
  for pattern in patterns:
    pattern_type = pattern.get("type") 
    if pattern_type:
      stats[pattern_type] += 1
  total = sum(stats.values())
  # Display using Rich
  console = Console()
  table = Table(title="Filtered Result")
  table.add_column("Type", style="cyan", no_wrap=True)
  table.add_column("Count", justify="right", style="magenta")

  for type_name, count in sorted(stats.items(), key=lambda x: -x[1]):
    table.add_row(type_name, str(count))
  table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")
  console.print(table)

  return dict(stats)

def save_filtered_patterns_to_csv(filtered_patterns, output_file="filtered_patterns.csv"):
  """
  Save selected fields from filtered patterns to a CSV file.

  Parameters:
    filtered_patterns (list): List of pattern dicts.
    output_file (str): Output file name (default: "filtered_patterns.csv")
  """
  with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["name", "pattern", "score_average", "type"])

    for pattern in filtered_patterns:
      name = pattern.get("name", "")
      value = pattern.get("value", "")
      scores = pattern.get("score", [])
      average_score = round(sum(scores) / len(scores), 2) if scores else 0
      ptype = pattern.get("type", "")

      writer.writerow([name, value, average_score, ptype])

def parse_args():
  parser = argparse.ArgumentParser(
    description="The Matrix Prompt Injection Tool (MPIT) - Generate, Apply, or Simulate prompt injection attacks.",
    epilog="""
    Examples:
      G Mode (Generate): python mpit.py G 
      A Mode (Apply):    python mpit.py A --url https://example.com --real-victim-curl-file victim.curl
                                          --attempt-per-attack 2 --no-sqli --score-filter 8.0
      S Mode (Simulate): python mpit.py S --system-prompt-file prompt.txt --temperature 0.7
                                          --no-rce --no-mdi --score-filter 9.0
    """,
    formatter_class=argparse.RawTextHelpFormatter
  )

  # Mode selection: G = Generate, A = Apply, S = Simulate
  parser.add_argument("mode", choices=["G", "A", "S"], help="Mode: G (Generate), A (Apply), S (Simulate)")

  # Apply mode parameters
  parser.add_argument("--url", type=str, help="A:Target base URL for Apply mode.")
  parser.add_argument("--real-victim-curl-file", type=str, help="A:File path containing real victim curl command.")

  # Simulate mode parameters
  parser.add_argument("--system-prompt-file", type=str, help="S:File path containing simulated victim system prompt.")
  parser.add_argument("--temperature", type=float, default=0.4, help="S:Temperature for simulated LLM (0.0 - 1.0)")

  parser.add_argument("--attempt-per-attack", type=int, default=1, help="AS: Number of attempts per attack (default: 1)")

  # Common options for all modes
  
  parser.add_argument("--no-mdi", action="store_true", default=False, help="Disable MDI test (default: False).")
  parser.add_argument("--no-prompt-leaking", action="store_true", default=False, help="Disable prompt leaking test (default: False).")
  parser.add_argument("--no-freellm", action="store_true", default=False, help="Disable FreeLLM test (default: False).")
  parser.add_argument("--no-xss", action="store_true", default=False, help="Disable XSS test (default: False).")
  parser.add_argument("--no-rce", action="store_true", default=False, help="Disable RCE test (default: False).")
  parser.add_argument("--no-sqli", action="store_true", default=False, help="Disable SQLi test (default: False).")

  parser.add_argument("--score-filter", type=float, default=9.0, help="Minimum score threshold to filter attack patterns (default: 9.0).")
  # Show help if no arguments are provided
  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

  args = parser.parse_args()

  # Mode-specific validations
  if args.mode == "A":
    if not args.url or not args.real_victim_curl_file:
      parser.error("Mode 'A' requires --url and --real_victim_curl_file.")

  elif args.mode == "S":
    if not args.system_prompt_file:
      parser.error("Mode 'S' requires --system_prompt_file.")
    if not (0.0 <= args.temperature <= 1.0):
      parser.error("Temperature must be between 0.0 and 1.0.")

  return args

if __name__ == "__main__":
  print_logo()
  args=parse_args()
  
  pattern_seeds = load_pattern_files()
  attack_patterns = combine_patterns(pattern_seeds)
  printl(f"Total attack patterns generated: {len(attack_patterns)}", "info")
  # printl("Saving all attack patterns to 'all_attack_patterns.json'...", "info")
  # with open("all_attack_patterns.json", 'w', encoding='utf-8') as file:
  #  json.dump(attack_patterns, file, indent=2, ensure_ascii=False)
  
  filter_type=[]
  if not args.no_freellm:
    filter_type.append("freellm")
  if not args.no_prompt_leaking:
    filter_type.append("prompt_leaking")
  if not args.no_xss:
    filter_type.append("xss")
  if not args.no_rce:
    filter_type.append("rce")
  if not args.no_sqli:
    filter_type.append("sqli")
  if not args.no_mdi:
    filter_type.append("mdi")

  filter_criteria = {
    "score_filter": args.score_filter,
    "type": filter_type
  }

  filtered_patterns = filter_patterns(attack_patterns, filter_criteria)
  printl(f"Filtered attack patterns with average score >= {args.score_filter}: {len(filtered_patterns)}", "info")
  statistics = get_statistics(filtered_patterns)
  with open("filtered_attack_patterns.json", 'w', encoding='utf-8') as file:
    json.dump(filtered_patterns, file, indent=2, ensure_ascii=False)
  printl("Filtered attack patterns saved to 'filtered_attack_patterns.json'.", "info")
  save_filtered_patterns_to_csv(filtered_patterns, "filtered_attack_patterns.csv")
  printl("Filtered attack patterns saved to 'filtered_attack_patterns.csv'.", "info")


