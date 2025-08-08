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
from mpit_generate_send_http_request import generate_send_http_request_function, generate_send_clear_conversation_function
from mpit_generate_expected_input import generate_expected_input_from_system_prompt, generate_expected_input_from_target_url

PROMPT_LEAK_LENGTH_ZSCORE_THRESHOLD = 0.854760444033574

def is_json(response_text):
  try:
    json.loads(response_text)
    return True
  except json.JSONDecodeError:
    return False

def load_pattern_files(dir)->dict:
  """
  Load pattern files from the patterns directory.
  Returns:
    dict: A dictionary containing lists of patterns from different categories.
    Each key is the pattern type, and the value is a list of dictionaries with pattern details.
    
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
    with open(f"{dir}/{file}", 'r', encoding='utf-8') as f:
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
              pattern_string += " " + delimiter["value"]
              # Exploit
              if delimiter["value"] == "":
                if expected_input["capital"]:
                  pattern_string += " " + exploit["value"].capitalize()
                else:
                  pattern_string += " " + exploit["value"]
              else:
                if delimiter["capital"]:
                  pattern_string += " " + exploit["value"].capitalize()
                else:
                  pattern_string += " " + exploit["value"]
              # New Instruction
              if exploit=="":
                if delimiter=="":
                  if expected_input["capital"]:
                    pattern_string += " " + new_instruction["value"].capitalize()
                  else:
                    pattern_string += " " + new_instruction["value"]  
                else:
                  if delimiter["capital"]:
                    pattern_string += " " + new_instruction["value"].capitalize()
                  else:
                    pattern_string += " " + new_instruction["value"]
              if exploit["capital"]:
                pattern_string += " " + new_instruction["value"].capitalize()
              else:
                pattern_string += " " + new_instruction["value"]
              # Reason
              if new_instruction["capital"]:
                pattern_string += " " + reason["value"].capitalize()
              else:
                pattern_string += " " + reason["value"]
              if "closing" in delimiter:
                pattern_string += " " + delimiter["closing"]
              
              attack_patterns.append({
                "name": f"{expected_input['name']}_{delimiter['name']}_{exploit['name']}_{new_instruction['name']}_{reason['name']}",
                "value": pattern_string,
                "score": (expected_input["score"] or [0.0]) + (delimiter["score"] or [0.0]) + (exploit["score"] or [0.0]) \
                  + (new_instruction["score"] or [0.0]) + (reason["score"] or [0.0]),
                "verify": new_instruction["verify"],
                "type": new_instruction["type"]
              })
            progress.advance(task)
  return attack_patterns

import heapq
from rich.progress import Progress
from typing import List, Dict, Any

def filter_patterns(
    attack_patterns: List[Dict[str, Any]],
    filter_criteria: Dict[str, Any],
    minimum_pattern_count: int
) -> List[Dict[str, Any]]:
    """
    Filter attack patterns based on the average score threshold and enabled attack types,
    but always return at least `minimum_pattern_count` patterns (falling back to the top-N
    by score if the threshold filter is too strict).

    Parameters:
      attack_patterns: List of dicts with keys "score" (list of floats) and "type" (str).
      filter_criteria: {
        "score_filter": float,
        "type": List[str]
      }
      minimum_pattern_count: Minimum number of patterns to return.

    Returns:
      A list of attack-pattern dicts (length >= minimum_pattern_count).
    """
    score_threshold = filter_criteria["score_filter"]
    allowed_types = set(filter_criteria["type"])

    # We'll store tuples of (avg_score, pattern) for those with valid scores & types
    scored_patterns = []

    with Progress() as progress:
        task = progress.add_task("[green]Scanning patterns…", total=len(attack_patterns))

        for pattern in attack_patterns:
            progress.update(task, advance=1)

            # Quick type check
            ptype = pattern.get("type")
            if ptype not in allowed_types:
                continue

            scores = pattern.get("score")
            if not scores:
                continue

            # compute average once
            avg = sum(scores) / len(scores)

            # save for later: we'll use it both for threshold-filter and for fallback top-N
            scored_patterns.append((avg, pattern))

    # First, try strict threshold
    above_threshold = [p for avg, p in scored_patterns if avg >= score_threshold]

    if len(above_threshold) >= minimum_pattern_count:
        return above_threshold

    # Fallback: pick the top `minimum_pattern_count` by avg score
    # heapq.nlargest is O(n log k), good even for n=3.6M when k is much smaller.
    top_k = heapq.nlargest(minimum_pattern_count, scored_patterns, key=lambda x: x[0])
    return [pattern for _, pattern in top_k]


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

def calculate_split_threshold(data) -> float:
  data = np.array(data)
  centroids = np.array([data.min(), data.max()])

  for _ in range(100):
    distances = np.abs(data[:, np.newaxis] - centroids[np.newaxis, :])
    labels = np.argmin(distances, axis=1)
    new_centroids = np.array([
      data[labels == i].mean() if np.any(labels == i) else centroids[i]
      for i in range(2)
    ])
    if np.allclose(centroids, new_centroids):
      break
    centroids = new_centroids
  printl(f"Prompt Leaking Border: {centroids.mean()}", "info")
  return centroids.mean() #split_threshold

def detect_prompt_leaking_by_length(mpit_results: list[str], target_result, split_threshold=0) -> bool:
  """
  Detect prompt leaking by checking if the length of the attack result matches the target result.
  
  Parameters:
    attack_results (list[str]): List of attack results to check.
    target_result (str): The expected result to compare against.
  
  Returns:
    bool: True if prompt leaking is detected, False otherwise.
  """
  response_lengths = [
    len(item["responses"])
    for item in mpit_results
    if item.get("type") == "prompt_leaking"
  ]

  if not response_lengths:
    return False, 0  # No reference data
  target_length = len(target_result)
  all_lengths = response_lengths
  if split_threshold == 0:
    split_threshold = calculate_split_threshold(all_lengths)
  printl(f"Target length: {target_length}, Split number: {split_threshold}", "debug")
  is_leaking = target_length > split_threshold
  return is_leaking, split_threshold
  
def parse_args():
  parser = argparse.ArgumentParser(
    description="The Matrix Prompt Injection Tool (MPIT) - Generate, Simulate or Attack prompt injection attacks.",
    epilog="""
    Examples:
      G Mode (Generate): python mpit.py G --score-filter 8.0 --no-rce
      S Mode (Simulate): python mpit.py S --system-prompt-file samples/systemprompt.txt --prompt-leaking-keywords "SunsetVoyager#3971"
                                          --attempt-per-attack 3 --score-filter 10 --no-sqli --no-rce
      A Mode (Attack):   python mpit.py A --target-url https://www.shinohack.me/shinollmapp/bella/ 
                                          --target-curl-file samples/bella_curl.txt
                                          --attempt-per-attack 2 --score-filter 10 --prompt-leaking-keywords "4551574n4"
      E Mode (Enhance):  python mpit.py E --system-prompt-file samples\bella_generic_ai_assistant\system_prompt.txt 
    """,
    formatter_class=argparse.RawTextHelpFormatter
  )

  # Mode selection: G = Generate, S = Simulate, A = Attack, E = Enhance
  parser.add_argument("mode", choices=["G", "A", "S", "E"], help="Mode: G (Generate), A (Attack), S (Simulate), E (Enhance)")

  # Attack mode parameters
  parser.add_argument("--target-url", type=str, help="A:Target base URL for Attack mode.")
  parser.add_argument("--target-curl-file", type=str, help="A:File path containing real victim curl command.")
  parser.add_argument("--target-clear-curl-file", type=str, help="A:File path containing clear conversation curl command to reset the conversation state.")

  # Simulate mode parameters
  parser.add_argument("--system-prompt-file", type=str, help="SE:File path containing simulated victim system prompt.")
  parser.add_argument("--model", type=str, default="gpt-4.1-nano", help="SE:Model to use for simulation (default: gpt-4.1-nano).")
  parser.add_argument("--temperature", type=float, default=1, help="SE:Temperature for simulated LLM (0.0 - 1.0)")

  # Enhance mode parameters
  parser.add_argument(
    "--exclude-seed-types", type=str, default="",
    help="E:Comma-separated list of seed types to exclude from Enhancement"
  )
  parser.add_argument(
      "--target-seed-counts", type=str, default="",
      help="E:Comma-separated seed type target counts, e.g. delimiter=10,exploit=20,new_instruction_xss=3,new_instruction_xss.reason=4"
  )
  parser.add_argument("--attempt-per-test", type=int, default=10, help="E: Number of attempts per attack in Enhance mode (default: 10)")
  parser.add_argument("--overgeneration-ratio", type=float, default=0.3, help="Ratio of generated seeds exceeding target count, relative to target count; actual number rounded up (default: 0.3)")
  parser.add_argument("--derivation-ratio", type=float, default=0.5,
                      help="E: Probability of each generated seed deriving from an existing seed (default: 0.5)")
  parser.add_argument(
      "--score-moving-average-window", type=int, default=1,
      help="E: Moving average window size for score calculation (default: 1)"
  )

  # Attack and Simulate mode common parameters
  parser.add_argument("--attempt-per-attack", type=int, default=1, help="AS: Number of attempts per attack in Attack and Simulate modes (default: 1)")
  parser.add_argument("--minimum-pattern-count", type=int, default=0, help="AS: Guaranteed number of top patterns used, regardless of score filter (default: 0)")
  parser.add_argument("--prompt-leaking-keywords", type=str, default="", help="ASE: A list of keywords to check for prompt leaking, separated by commas (default: empty).")

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

  if args.minimum_pattern_count < 0:
    printl("Minimum pattern count must be at least 0.", "error")
    exit(1)
  
  # Mode-specific validations
  if args.mode == "A":
    if not args.target_url or not args.target_curl_file:
      printl("Mode 'A' requires --target-url and --target-curl-file.", "error")
      exit(1)
    elif not os.path.exists(args.target_curl_file):
      printl(f"Target curl file '{args.target_curl_file}' does not exist.", "error")
      exit(1)
    if args.target_clear_curl_file:
      if not os.path.exists(args.target_clear_curl_file):
        printl(f"Target clear curl file '{args.target_clear_curl_file}' does not exist.", "error")
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
    "log_file": log_file,
    "dump_all_attack": args.dump_all_attack
  }
  with open(f"{report_dir}/mpit_configuration.json", 'w', encoding='utf-8') as file:
    json.dump(mpit_configuration, file, indent=2, ensure_ascii=False)
  
  pattern_seeds = load_pattern_files("patterns")
  
  # Generate expected input based on system prompt or target URL
  expected_input_path=os.path.join(report_dir, "expected_input.txt")
  if args.mode == "S":
    printl(f"Generating expected input from system prompt.", "info")
    expected_input= generate_expected_input_from_system_prompt(args.system_prompt_file, expected_input_path) + " "
    if not expected_input:
      printl("Failed to generate expected input from system prompt.", "error")
      exit(1)
    pattern_seeds["expected_input"].append({"name": "llmgen", "value": expected_input, "capital": True, "score": [10.001], })
  
  if args.mode == "A":
    # Generate "Expected Input" based on target URL
    printl(f"Generating expected input from target URL: {args.target_url}", "info")
    expected_input = generate_expected_input_from_target_url(args.target_url, expected_input_path) + " "
    if not expected_input:
      printl("Failed to generate expected input from target URL.", "error")
      exit(1)
    pattern_seeds["expected_input"].append({"name": "llmgen", "value": expected_input, "capital": True, "score": [10.001], })
  
  if args.mode == "E":
    from mpit_enhance import run_enhance_mode
    args.no_sqli = True
    args.no_rce = True
    run_enhance_mode(args, report_dir)
    exit(0)
  
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

  filtered_patterns = filter_patterns(attack_patterns, filter_criteria, args.minimum_pattern_count)
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
  
  # Attack mode
  if args.mode == "A":
    target={
      "url": args.target_url
    }
    with open(args.target_curl_file, "r", encoding="utf-8") as file:
      target_curl = file.read().strip()
    printl(f"{args.target_curl_file} loaded.", "info")
    curl_command_path=os.path.join(report_dir, "target_curl.txt")
    with open(curl_command_path, "w", encoding="utf-8") as file:
      file.write(target_curl)
    printl(f"{curl_command_path} saved.", "info")
    send_http_request_function_path = f"{report_dir}/post_function.py"
    send_http_request = generate_send_http_request_function(target_curl, send_http_request_function_path)
    if send_http_request:
      printl(f"Post function generated successfully and saved as {send_http_request_function_path}", "info")
    else:
      printl("Failed to generate post function.", "critical")
      exit(1)
      
    if args.target_clear_curl_file:
      
      with open(args.target_clear_curl_file, "r", encoding="utf-8") as file:
        target_clear_curl = file.read().strip()
      printl(f"{args.target_clear_curl_file} loaded.", "info")
      clear_conversation_function_path = f"{report_dir}/clear_conversation_function.py"
      send_clear_conversation = generate_send_clear_conversation_function(target_clear_curl, clear_conversation_function_path)
      if send_clear_conversation:
        printl(f"Clear conversation function generated successfully and saved as {clear_conversation_function_path}", "info")
      else:
        printl("Failed to generate clear conversation function.", "critical")
        exit(1)

  # Simulate mode
  if args.mode == "S":
    with open(args.system_prompt_file, "r", encoding="utf-8") as file:
      system_prompt = file.read().strip()
    target={
      "system_prompt": system_prompt
    }
    printl(f"System prompt loaded from {args.system_prompt_file}.", "info")
    # Copy the system prompt to the report directory
    with open(f"{report_dir}/system_prompt.txt", "w", encoding="utf-8") as file:
      file.write(system_prompt)
    printl("System prompt copied to report directory.", "info")
  
  # Start Pattern Testing
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
      if args.mode == "A":
        responses=[]
        for i in range(attempt_per_attack):
          if args.target_clear_curl_file:
            printl(f"Clearing conversation state for pattern {pattern['name']} on attempt {i+1}.", "debug")
            clear_response = send_clear_conversation()
            if clear_response and isinstance(clear_response, dict) and "html" in clear_response:
              printl(f"Conversation cleared successfully for pattern {pattern['name']} on attempt {i+1}.", "debug")
          printl(f"Sending HTTP request for pattern {pattern['name']} on attempt {i+1}.", "debug")
          response = send_http_request(pattern['value'])
          if response and isinstance(response, dict) and "html" in response:
            response_html = response["html"]
            if is_json(response_html):
              response_html = json.dumps(json.loads(response_html), indent=2, ensure_ascii=False)
            response_html=response_html.replace(pattern['value'], "{ATTACK_PATTERN}")  
            response_html=response_html.replace(json.dumps(pattern['value']), "{ATTACK_PATTERN}")
            responses.append(response_html)
          else:
            printl(f"Error in response for pattern {pattern['name']} on attempt {i+1}: {response}", "error")
      
      if args.mode == "S":
        messages = [
          {"role": "system", "content": system_prompt},
          {"role": "user", "content": f"{pattern['value']}\n###"}
        ]
        printl(f"Simulating attack with pattern: {pattern['name']}", "debug")
        responses = get_openai_responses(messages, n=attempt_per_attack, model=args.model, temperature=args.temperature, )
      
        
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
  
  # Prompt Leaking Detection
  with Progress(
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    TextColumn("Processed: [cyan]{task.completed}/{task.total}"),
  ) as progress:
    task = progress.add_task("[green]Detecting prompt leaking...", total=len(mpit_results))
    split_threshold = 0
    for result in mpit_results:
      if result["type"] == "prompt_leaking" and not result["attack_success"]:
        printl(f"Detecting prompt leaking for pattern: {result['name']}", "debug")
        is_leaking, split_threshold = detect_prompt_leaking_by_length(mpit_results, result["responses"], split_threshold)
        if is_leaking:
          result["attack_success"] = True
          printl(f"  Prompt leaking detected for pattern: {result['name']}", "debug")
        else:
          result["attack_success"] = False
      progress.advance(task)
  
  
  # Save the results to JSON and CSV files
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
  html_report_path = os.path.join(report_dir, "mpit_report.html")
  
  generate_html_report(mpit_results, attack_period_start, attack_period_end, target, html_report_path)
  printl(f"{html_report_path} saved.", "info")
  webbrowser.open(html_report_path)