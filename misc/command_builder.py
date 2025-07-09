import gradio as gr
def build_command(
  mode,
  target_url, target_curl_file, target_clear_curl_file,
  system_prompt_file, model, temperature,
  attempt_per_attack, keywords,
  no_mdi, no_prompt_leaking, no_osr, no_xss, no_rce, no_sqli,
  dump_all_attack, score_filter
):
  mode_map = {
    "[G]enerate patterns": "G",
    "[A]ttack the LLM app": "A",
    "[S]imulate attack": "S"
  }
  m = mode_map[mode]

  # Validation
  if m == "A":
    if not target_url:
      return "❌ Error: Target URL is required for Attack mode"
    if not target_curl_file:
      return "❌ Error: Victim curl file is required for Attack mode"
  if m == "S":
    if not system_prompt_file:
      return "❌ Error: System prompt file is required for Simulate mode"

  # Build command
  cmd = f"python mpit.py {m}"
  if m == "A":
    cmd += f" --target-url {target_url}"
    cmd += f" --target-curl-file \"{target_curl_file.name}\""
    if target_clear_curl_file:
      cmd += f" --target-clear-curl-file \"{target_clear_curl_file.name}\""
  if m == "S":
    cmd += f" --system-prompt-file \"{system_prompt_file.name}\""
    cmd += f" --model {model}"
    cmd += f" --temperature {temperature}"
  if m in ("A", "S"):
    if attempt_per_attack != 1:
      cmd += f" --attempt-per-attack {int(attempt_per_attack)}"
    if keywords:
      cmd += f" --prompt-leaking-keywords \"{keywords}\""

  if no_mdi: cmd += " --no-mdi"
  if no_prompt_leaking: cmd += " --no-prompt-leaking"
  if no_osr: cmd += " --no-osr"
  if no_xss: cmd += " --no-xss"
  if no_rce: cmd += " --no-rce"
  if no_sqli: cmd += " --no-sqli"
  if dump_all_attack: cmd += " --dump-all-attack"
  if score_filter != 10:
    cmd += f" --score-filter {score_filter}"

  return cmd

with gr.Blocks() as demo:
  gr.Markdown("# 🧪 Matrix Prompt Injection Tool (MPIT) UI")

  mode = gr.Radio(
    ["[G]enerate patterns", "[S]imulate attack", "[A]ttack the LLM app"],
    label="Choose Mode",
    value="[G]enerate patterns"
  )

  gr.Markdown("### 🛠️ Common Options (applies to all modes)")
  no_mdi = gr.Checkbox(label="Skip Markdown Injection test (--no-mdi)")
  no_prompt_leaking = gr.Checkbox(label="Skip Prompt Leaking test (--no-prompt-leaking)")
  no_osr = gr.Checkbox(label="Skip Out-of-Scope Request test (--no-osr)")
  no_xss = gr.Checkbox(label="Skip Cross-Site Scripting (XSS) test (--no-xss)")
  no_rce = gr.Checkbox(label="Skip Remote Code Execution (RCE) test (--no-rce)")
  no_sqli = gr.Checkbox(label="Skip SQL Injection test (--no-sqli)")
  dump_all_attack = gr.Checkbox(label="Dump all generated attacks to file (--dump-all-attack)")
  score_filter = gr.Slider(0, 10, value=10, step=0.5, label="Minimum score threshold for attacks (default: 10)")

  gr.Markdown("### 🎯 Mode-Specific Configuration")

  with gr.Column(visible=False) as shared_as_group:
    attempt_per_attack = gr.Number(value=1, label="Number of attempts per attack (default: 1)", precision=0)
    keywords = gr.Textbox(label="Prompt leaking keywords (comma-separated, optional)")

  with gr.Column(visible=False) as simulate_group:
    system_prompt_file = gr.File(label="🔴 System prompt file (.txt)", file_types=[".txt"])
    model = gr.Textbox(label="Model to simulate (default: gpt-4.1-nano)", value="gpt-4.1-nano")
    temperature = gr.Slider(0.0, 1.0, value=1.0, step=0.1, label="Temperature for LLM randomness")

  with gr.Column(visible=False) as attack_group:
    target_url = gr.Textbox(label="🔴 Target URL to send attack")
    target_curl_file = gr.File(label="🔴 Victim curl command file (.txt)", file_types=[".txt"])
    target_clear_curl_file = gr.File(label="Clear state curl file (.txt)", file_types=[".txt"])

  output = gr.Textbox(label="🧾 Generated Command", lines=3, show_copy_button=True)
  btn = gr.Button("🛠️ Generate mpit.py Command")

  def toggle_fields(m):
    return {
      shared_as_group: gr.update(visible=m in ["[A]ttack the LLM app", "[S]imulate attack"]),
      simulate_group: gr.update(visible=m == "[S]imulate attack"),
      attack_group: gr.update(visible=m == "[A]ttack the LLM app"),
    }

  mode.change(fn=toggle_fields, inputs=[mode], outputs=[shared_as_group, simulate_group, attack_group])

  btn.click(
    fn=build_command,
    inputs=[
      mode, target_url, target_curl_file, target_clear_curl_file,
      system_prompt_file, model, temperature,
      attempt_per_attack, keywords,
      no_mdi, no_prompt_leaking, no_osr, no_xss, no_rce, no_sqli,
      dump_all_attack, score_filter
    ],
    outputs=output
  )

demo.launch(inbrowser=True)