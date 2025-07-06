import os
import re
import csv
import sys
import json
import argparse
import numpy as np
from datetime import datetime
import webbrowser
from rich.progress import Progress, TextColumn, BarColumn, TimeRemainingColumn
from rich.console import Console
from rich.table import Table
from collections import defaultdict


from mpit_ascii import print_logo
from mpit_logger import printl, log_file
from mpit_openai import get_openai_responses
from mpit_report import generate_html_report

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
    "new_instruction_osr.json",
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
  
  attack_patterns =[]

  with Progress() as progress:
    task = progress.add_task("[green]Loading attack patterns...", total=total)
    for expected_input in pattern_seeds["expected_input"]:
      for delimiter in pattern_seeds["delimiter"]:
        for exploit in pattern_seeds["exploit"]:
          for new_instruction in pattern_seeds["new_instruction"]:
            for reason in new_instruction["reason"]:
              # Expected Input
              pattern_string = expected_input["value"].capitalize()
              # Delimiter
              pattern_string += delimiter["value"]
              # Exploit
              if delimiter["value"] == "":
                if expected_input["capital"]:
                  pattern_string += exploit["value"].capitalize()
                else:
                  pattern_string += exploit["value"]
              else:
                if delimiter["capital"]:
                  pattern_string += exploit["value"].capitalize()
                else:
                  pattern_string += exploit["value"]
              # New Instruction
              if exploit=="":
                if delimiter=="":
                  if expected_input["capital"]:
                    pattern_string += new_instruction["value"].capitalize()
                  else:
                    pattern_string += new_instruction["value"]  
                else:
                  if delimiter["capital"]:
                    pattern_string += new_instruction["value"].capitalize()
                  else:
                    pattern_string += new_instruction["value"]
              if exploit["capital"]:
                pattern_string += new_instruction["value"].capitalize()
              else:
                pattern_string += new_instruction["value"]
              # Reason
              if new_instruction["capital"]:
                pattern_string += reason["value"].capitalize()
              else:
                pattern_string += reason["value"]
              if "closing" in delimiter:
                pattern_string += delimiter["closing"]
              
              attack_patterns.append({
                "name": f"{expected_input['name']}_{delimiter['name']}_{exploit['name']}_{new_instruction['name']}_{reason['name']}",
                "value": pattern_string,
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


def save_filtered_patterns_to_csv(filtered_patterns, output_file="filtered_patterns.csv"):
  """
  Save selected fields from filtered patterns to a CSV file.

  Parameters:
    filtered_patterns (list): List of pattern dicts.
    output_file (str): Output file name (default: "filtered_patterns.csv")
  """
  try:
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
      writer = csv.writer(csvfile)
      writer.writerow(["name", "pattern", "score_average", "type"])

      for pattern in filtered_patterns:
        name = pattern.get("name", "")
        value = pattern.get("value", "")
        scores = pattern.get("score", [])
        average_score = round(sum(scores) / len(scores), 2) if scores else 0
        ptype = pattern.get("type", "")

        writer.writerow([name, value, average_score, ptype])
    return True
  except Exception as e:
    printl(f"Error saving to CSV: {e}", "error")
    return False

def save_mpit_results_to_csv(mpit_results, output_file="mpit_results.csv"):
  """
  Save MPIT results to a CSV file.

  Parameters:
    mpit_results (list): List of dictionaries containing MPIT results.
    output_file (str): Output file name (default: "mpit_results.csv")
  """
  try:
    with open(output_file, "w", newline="", encoding="utf-8-sig") as csvfile:
      writer = csv.writer(csvfile)
      writer.writerow(["type", "name", "value", "responses", "attack_success", "average_score", "score"])

      for result in mpit_results:
        type_name = result.get("type", "")
        name = result.get("name", "")
        value = result.get("value", "")
        responses = result.get("responses", "")
        attack_success = result.get("attack_success", False)
        average_score = sum(result.get("score", [0])) / len(result.get("score", 1)) 
        score = result.get("score", 0)
        writer.writerow([type_name, name, value, responses, attack_success, average_score, score])
    return True
  except Exception as e:
    printl(f"Error saving MPIT results to CSV: {e}", "error", e)
    return False

def get_attack_pattern_statistics(patterns: list) -> dict:
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

def verify_attack_patterns(llm_outputs: list[str], verifies: list[dict], prompt_leaking_keywords:list[str]) -> list[bool]:
  """
  Verify attack patterns against LLM outputs using regex patterns.
  Parameters:
    llm_outputs (list[str]): List of LLM output strings to verify.
    verifies (list[dict]): List of verification patterns, each dict should have:
      - "type": "regex"
      - "pattern": regex pattern string
    prompt_leaking_keywords (list[str]): List of keywords to check for prompt leaking.
  """
  for keyword in prompt_leaking_keywords:
    verifies.append({
      "type": "regex",
      "pattern": rf"{re.escape(keyword)}"
    })
  attack_results = [False] * len(llm_outputs)
  for i, output in enumerate(llm_outputs):
    for j, verify in enumerate(verifies):
      if verify['type'] == "regex":
        regex = re.compile(verify['pattern'], re.IGNORECASE)
        if regex.search(output):
          attack_results[i] = True
          break
  return attack_results
  

def parse_args():
  parser = argparse.ArgumentParser(
    description="The Matrix Prompt Injection Tool (MPIT) - Generate, Simulate or Attack prompt injection attacks.",
    epilog="""
    Examples:
      G Mode (Generate): python mpit.py G --score-filter 8.0 --no-rce
      S Mode (Simulate): python mpit.py S --system-prompt-file samples/systemprompt.txt --prompt-leaking-keywords "SunsetVoyager#3971"
                                          --attempt-per-attack 3 --score-filter 10 --no-sqli --no-rce
      A Mode (Attack):   python mpit.py A --target-url https://example.com --target-curl-file victim.curl
                                          --attempt-per-attack 2 --no-sqli --score-filter 8.0
    """,
    formatter_class=argparse.RawTextHelpFormatter
  )

  # Mode selection: G = Generate, S = Simulate, A = Attack
  parser.add_argument("mode", choices=["G", "A", "S"], help="Mode: G (Generate), A (Attack), S (Simulate)")

  # Attack mode parameters
  parser.add_argument("--target-url", type=str, help="A:Target base URL for Attack mode.")
  parser.add_argument("--target-curl-file", type=str, help="A:File path containing real victim curl command.")

  # Simulate mode parameters
  parser.add_argument("--system-prompt-file", type=str, help="S:File path containing simulated victim system prompt.")
  parser.add_argument("--temperature", type=float, default=1, help="S:Temperature for simulated LLM (0.0 - 1.0)")

  # Attack and Simulate mode common parameters
  parser.add_argument("--attempt-per-attack", type=int, default=1, help="AS: Number of attempts per attack (default: 1)")
  parser.add_argument("--prompt-leaking-keywords", type=str, default=1, help="AS: A list of keywords to check for prompt leaking, separated by commas (default: empty).")

  # Common options for all modes
  parser.add_argument("--no-mdi", action="store_true", default=False, help="Disable MDI test (default: False).")
  parser.add_argument("--no-prompt-leaking", action="store_true", default=False, help="Disable prompt leaking test (default: False).")
  parser.add_argument("--no-osr", action="store_true", default=False, help="Disable Out-of-scope request test (default: False).")
  parser.add_argument("--no-xss", action="store_true", default=False, help="Disable XSS test (default: False).")
  parser.add_argument("--no-rce", action="store_true", default=False, help="Disable RCE test (default: False).")
  parser.add_argument("--no-sqli", action="store_true", default=False, help="Disable SQLi test (default: False).")
  
  # Experimental options
  parser.add_argument("--dump-all-attack", action="store_true", default=False, help="Dump all attack patterns to a file (default: False).")

  parser.add_argument("--score-filter", type=float, default=10, help="Minimum score threshold to filter attack patterns (default: 9.0).")
  # Show help if no arguments are provided
  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

  args = parser.parse_args()

  # Validate temperature value
  if args.temperature < 0.0 or args.temperature > 2.0:
    printl("Temperature must be between 0.0 and 2.0.", "error")
    exit(1)

  # Validate score filter value
  if args.score_filter < 0.0 or args.score_filter > 11.0:
    printl("Score filter must be between 0.0 and 10.0.", "error")
    exit(1)
  
  # Validate attempt per attack value
  if args.attempt_per_attack < 1:
    printl("Attempt per attack must be at least 1.", "error")
    exit(1)
  
  # Mode-specific validations
  if args.mode == "A":
    if not args.url or not args.real_victim_curl_file:
      printl("Mode 'A' requires --target-url and --target-curl-file.", "error")
      exit(1)

  elif args.mode == "S":
    if not args.system_prompt_file:
      printl("Mode 'S' requires --system-prompt-file.", "error")
      exit(1)
    elif not os.path.exists(args.system_prompt_file):
      printl(f"System prompt file '{args.system_prompt_file}' does not exist.", "error")
      exit(1)
    if not (0.0 <= args.temperature <= 1.0):
      printl("Temperature must be between 0.0 and 1.0.", "error")
      exit(1)

  return args

if __name__ == "__main__":
  print_logo()
  args=parse_args()
  
  #### Create a dir "reports\YYYY-MM-DD_HHMMSS" to save the results
  timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
  report_dir = f"reports/{timestamp}"
  os.makedirs(report_dir, exist_ok=True)
  printl(f"Report directory created: {report_dir}", "info")
  
  # Save the configuration to a JSON file
  mpit_configuration = {
    "commandline": "python " + " ".join(sys.argv),
    "mode": args.mode,
    "target_url": args.target_url,
    "target_curl_file": args.target_curl_file,
    "system_prompt_file": args.system_prompt_file,
    "temperature": args.temperature,
    "attempt_per_attack": args.attempt_per_attack,
    "prompt_leaking_keywords": args.prompt_leaking_keywords,
    "no_mdi": args.no_mdi,
    "no_prompt_leaking": args.no_prompt_leaking,
    "no_osr": args.no_osr,
    "no_xss": args.no_xss,
    "no_rce": args.no_rce,
    "no_sqli": args.no_sqli,
    "score_filter": args.score_filter,
    "log_file": log_file
  }
  with open(f"{report_dir}/mpit_configuration.json", 'w', encoding='utf-8') as file:
    json.dump(mpit_configuration, file, indent=2, ensure_ascii=False)
  
  pattern_seeds = load_pattern_files()
  attack_patterns = combine_patterns(pattern_seeds)
  printl(f"Total attack patterns generated: {len(attack_patterns)}", "info")
  
  if args.dump_all_attack:
    all_patterns_path ="all_attack_patterns.json"
    with open(all_patterns_path, 'w', encoding='utf-8') as file:
      json.dump(attack_patterns, file, indent=2, ensure_ascii=False)
    printl(f"{all_patterns_path} saved.", "info")
  
  
  filter_type=[]
  if not args.no_osr:
    filter_type.append("osr")
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
  statistics = get_attack_pattern_statistics(filtered_patterns)
  filtered_patterns_path = os.path.join(report_dir, "filtered_attack_patterns.json")
  with open(filtered_patterns_path, 'w', encoding='utf-8') as file:
    json.dump(filtered_patterns, file, indent=2, ensure_ascii=False)
  printl(f"{filtered_patterns_path} saved.", "info")
  save_result=save_filtered_patterns_to_csv(filtered_patterns, filtered_patterns_path.replace(".json", ".csv"))
  if not save_result:
    printl("Failed to save filtered patterns to CSV.", "error")
    exit(1)
  printl(f"{filtered_patterns_path.replace('.json', '.csv')} saved.", "info")

  if args.mode == "G":
    exit(0) 

  # For S and A mode
  mpit_results=[]
  prompt_leaking_keywords = args.prompt_leaking_keywords.split(",") if args.prompt_leaking_keywords else []
  attempt_per_attack = args.attempt_per_attack if args.attempt_per_attack > 0 else 1
  # Simulate mode
  if args.mode == "S":
    with open(args.system_prompt_file, "r", encoding="utf-8") as file:
      system_prompt = file.read().strip()
    printl(f"System prompt loaded from {args.system_prompt_file}.", "info")
    # Copy the system prompt to the report directory
    with open(f"{report_dir}/system_prompt.txt", "w", encoding="utf-8") as file:
      file.write(system_prompt)
    printl("System prompt copied to report directory.", "info")
    
    success_count = 0
    attack_period_start = datetime.now()
    
    with Progress(
      TextColumn("[progress.description]{task.description}"),
      BarColumn(),
      TextColumn("Processed: [cyan]{task.completed}/{task.total}"),
      TextColumn("• Success: [green]{task.fields[success]}/" + str(len(filtered_patterns) * attempt_per_attack)),
      TimeRemainingColumn(),
    ) as progress:
      task = progress.add_task("[green]Simulating attacks...", total=len(filtered_patterns) * attempt_per_attack, success=success_count)
      for pattern in filtered_patterns:
        messages = [
          {"role": "system", "content": system_prompt},
          {"role": "user", "content": f"{pattern['value']}\n###"}
        ]
        printl(f"Simulating attack with pattern: {pattern['name']}", "debug")
        responses = get_openai_responses(messages, n= attempt_per_attack, temperature=args.temperature)
        attack_results = verify_attack_patterns(responses, pattern['verify'], prompt_leaking_keywords)
        if any(attack_results):
          printl(f"\tAttack pattern '{pattern['name']}' succeeded.", "debug")
        for i, response in enumerate(responses):
          mpit_results.append({
            "type": pattern["type"],
            "name": pattern["name"],
            "value": pattern["value"],
            "responses": response,
            "attack_success": attack_results[i],
            "score": pattern["score"]
          })
          if attack_results[i]:
            success_count += 1
        progress.update(task, advance=attempt_per_attack, success=success_count)
    attack_period_end = datetime.now()
    
    
    
  mpit_results_path = os.path.join(report_dir, "mpit_results.json")
  with open(mpit_results_path, 'w', encoding='utf-8') as file:
    json.dump(mpit_results, file, indent=2, ensure_ascii=False)
  printl(f"{mpit_results_path} saved", "info")
  save_result = save_mpit_results_to_csv(mpit_results, mpit_results_path.replace(".json", ".csv"))
  if not save_result:
    printl("Failed to save MPIT results to CSV.", "error")
    exit(1)
  printl(f"{mpit_results_path.replace('.json', '.csv')} saved.", "info")
  # Generate HTML report
  html_report_path = os.path.join(report_dir, "attack_report.html")
  generate_html_report(mpit_results, attack_period_start, attack_period_end, html_report_path)
  printl(f"{html_report_path} saved.", "info")
  webbrowser.open(html_report_path)