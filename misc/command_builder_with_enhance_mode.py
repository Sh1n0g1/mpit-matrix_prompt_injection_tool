import gradio as gr

def build_command(
  mode,
  target_url, target_curl_file, target_clear_curl_file,
  system_prompt_file, model, temperature,
  attempt_per_attack,  # A/S
  keywords,            # A/S/E
  # E-only
  exclude_seed_types, target_seed_counts, attempt_per_test,
  overgeneration_ratio, derivation_ratio, score_moving_average_window,
  # common toggles
  no_mdi, no_prompt_leaking, no_osr, no_xss, no_rce, no_sqli,
  dump_all_attack, score_filter
):
  mode_map = {
    "[G]enerate patterns": "G",
    "[A]ttack the LLM app": "A",
    "[S]imulate attack": "S",
    "[E]nhance patterns": "E"
  }
  m = mode_map[mode]

  # Validation
  if m == "A":
    if not target_url:
      return "❌ Error: Target URL is required for Attack mode"
    if not target_curl_file:
      return "❌ Error: Victim curl file is required for Attack mode"
  if m in ("S", "E"):
    if not system_prompt_file:
      return "❌ Error: System prompt file is required for Simulate/Enhance mode"

  # Build command
  cmd = f"python mpit.py {m}"

  # A: attack targets
  if m == "A":
    cmd += f" --target-url {target_url}"
    cmd += f" --target-curl-file \"{target_curl_file.name}\""
    if target_clear_curl_file:
      cmd += f" --target-clear-curl-file \"{target_clear_curl_file.name}\""

  # S/E: simulation params
  if m in ("S", "E"):
    cmd += f" --system-prompt-file \"{system_prompt_file.name}\""
    if model:
      cmd += f" --model {model}"
    if temperature is not None:
      cmd += f" --temperature {temperature}"

  # A/S: attempts per attack
  if m in ("A", "S"):
    if attempt_per_attack is not None and int(attempt_per_attack) != 1:
      cmd += f" --attempt-per-attack {int(attempt_per_attack)}"

  # E: enhancement-specific args
  if m == "E":
    if exclude_seed_types:
      cmd += f" --exclude-seed-types {exclude_seed_types}"
    if target_seed_counts:
      cmd += f" --target-seed-counts \"{target_seed_counts}\""
    # defaults per help: attempt-per-test=10, overgeneration=0.3, derivation=0.5, score MA window=1
    if attempt_per_test is not None and int(attempt_per_test) != 10:
      cmd += f" --attempt-per-test {int(attempt_per_test)}"
    if overgeneration_ratio is not None and float(overgeneration_ratio) != 0.3:
      cmd += f" --overgeneration-ratio {overgeneration_ratio}"
    if derivation_ratio is not None and float(derivation_ratio) != 0.5:
      cmd += f" --derivation-ratio {derivation_ratio}"
    if score_moving_average_window is not None and int(score_moving_average_window) != 1:
      cmd += f" --score-moving-average-window {int(score_moving_average_window)}"

  # ASE: keywords
  if keywords:
    cmd += f" --prompt-leaking-keywords \"{keywords}\""

  # Common toggles
  if no_mdi: cmd += " --no-mdi"
  if no_prompt_leaking: cmd += " --no-prompt-leaking"
  if no_osr: cmd += " --no-osr"
  if no_xss: cmd += " --no-xss"
  if no_rce: cmd += " --no-rce"
  if no_sqli: cmd += " --no-sqli"
  if dump_all_attack: cmd += " --dump-all-attack"
  if score_filter is not None and float(score_filter) != 10:
    cmd += f" --score-filter {score_filter}"

  return cmd


with gr.Blocks() as demo:
  gr.Markdown("# 🧪 Matrix Prompt Injection Tool (MPIT) UI")

  mode = gr.Radio(
    ["[G]enerate patterns", "[S]imulate attack", "[A]ttack the LLM app", "[E]nhance patterns"],
    label="Choose Mode",
    value="[G]enerate patterns"
  )

  gr.Markdown("### 🛠️ Common Options (apply to all modes)")
  no_mdi = gr.Checkbox(label="Skip Markdown Injection test (--no-mdi)")
  no_prompt_leaking = gr.Checkbox(label="Skip Prompt Leaking test (--no-prompt-leaking)")
  no_osr = gr.Checkbox(label="Skip Out-of-Scope Request test (--no-osr)")
  no_xss = gr.Checkbox(label="Skip Cross-Site Scripting (XSS) test (--no-xss)")
  no_rce = gr.Checkbox(label="Skip Remote Code Execution (RCE) test (--no-rce)")
  no_sqli = gr.Checkbox(label="Skip SQL Injection test (--no-sqli)")
  dump_all_attack = gr.Checkbox(label="Dump all generated attacks to file (--dump-all-attack)")
  score_filter = gr.Slider(0, 10, value=10, step=0.5, label="Minimum score threshold for attacks (default: 10)")
  keywords = gr.Textbox(label="Prompt leaking keywords (comma-separated, optional) — used in A/S/E")

  gr.Markdown("### 🎯 Mode-Specific Configuration")

  # A & S shared
  with gr.Column(visible=False) as shared_as_group:
    attempt_per_attack = gr.Number(value=1, label="Attempts per attack (A/S, default: 1)", precision=0)

  # S & E: uses simulated system prompt + model + temperature
  with gr.Column(visible=False) as simulate_group:
    system_prompt_file = gr.File(label="🔴 System prompt file (.txt)", file_types=[".txt"])
    model = gr.Textbox(label="Model for simulation (S/E, default: gpt-4.1-nano)", value="gpt-4.1-nano")
    temperature = gr.Slider(0.0, 1.0, value=1.0, step=0.1, label="Temperature for LLM randomness (S/E)")

  # A only
  with gr.Column(visible=False) as attack_group:
    target_url = gr.Textbox(label="🔴 Target URL to send attack")
    target_curl_file = gr.File(label="🔴 Victim curl command file (.txt)", file_types=[".txt"])
    target_clear_curl_file = gr.File(label="Clear state curl file (.txt)", file_types=[".txt"])

  # E only
  with gr.Column(visible=False) as enhance_group:
    exclude_seed_types = gr.Textbox(
      label="Exclude seed types (E) — comma-separated",
      placeholder="e.g., delimiter,exploit"
    )
    target_seed_counts = gr.Textbox(
      label="Target seed counts (E)",
      placeholder="e.g., delimiter=10,exploit=20,new_instruction_xss=3,new_instruction_xss.reason=4"
    )
    attempt_per_test = gr.Number(value=10, label="Attempts per test (E, default: 10)", precision=0)
    overgeneration_ratio = gr.Slider(0.0, 2.0, value=0.3, step=0.05, label="Overgeneration ratio (E, default: 0.3)")
    derivation_ratio = gr.Slider(0.0, 1.0, value=0.5, step=0.05, label="Derivation ratio (E, default: 0.5)")
    score_moving_average_window = gr.Number(value=1, label="Score moving average window (E, default: 1)", precision=0)

  output = gr.Textbox(label="🧾 Generated Command", lines=3, show_copy_button=True)
  btn = gr.Button("🛠️ Generate mpit.py Command")

  def toggle_fields(m):
    return {
      shared_as_group: gr.update(visible=m in ["[A]ttack the LLM app", "[S]imulate attack"]),
      simulate_group: gr.update(visible=m in ["[S]imulate attack", "[E]nhance patterns"]),
      attack_group: gr.update(visible=m == "[A]ttack the LLM app"),
      enhance_group: gr.update(visible=m == "[E]nhance patterns"),
    }

  mode.change(
    fn=toggle_fields,
    inputs=[mode],
    outputs=[shared_as_group, simulate_group, attack_group, enhance_group]
  )

  btn.click(
    fn=build_command,
    inputs=[
      mode,
      # A targets
      target_url, target_curl_file, target_clear_curl_file,
      # S/E sim
      system_prompt_file, model, temperature,
      # A/S only
      attempt_per_attack,
      # ASE common
      keywords,
      # E only
      exclude_seed_types, target_seed_counts, attempt_per_test,
      overgeneration_ratio, derivation_ratio, score_moving_average_window,
      # toggles + score
      no_mdi, no_prompt_leaking, no_osr, no_xss, no_rce, no_sqli,
      dump_all_attack, score_filter
    ],
    outputs=output
  )

demo.launch(inbrowser=True)
