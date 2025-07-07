import os
import sys
import html
import json
import pandas as pd
import plotly.express as px
import markdown
import webbrowser
from jinja2 import Template
from datetime import datetime
from mpit_openai import get_openai_responses


def generate_html_report(mpit_result, attack_period_start, attack_period_end, target, output_file="attack_report.html"):
  """
  Generates an HTML report from MPIT results.
  
  Args:
      mpit_result (dict): The MPIT results data.
      output_file (str): The file path to save the HTML report.
  """
    
  data = mpit_result
  df = pd.DataFrame(data)

  # 2. Data Analysis
  summary_by_type = df.groupby("type")["attack_success"].value_counts().unstack().fillna(0)
  summary_by_type.columns = ["Failure", "Success"]
  summary_by_type["Total"] = summary_by_type.sum(axis=1)
  summary_by_type["Success Rate (%)"] = (summary_by_type["Success"] / summary_by_type["Total"] * 100).round(1)
  type_order = ["rce", "sqli", "xss", "mdi", "prompt_leaking", "osr" ]
  summary_by_type = summary_by_type.reindex(type_order)
  
  start_str = attack_period_start.strftime("%Y-%m-%d %H:%M:%S")
  end_str = attack_period_end.strftime("%Y-%m-%d %H:%M:%S")

  # Generate Executive Summary
  system_prompt = """
  You are an expert in cybersecurity and prompt injection attacks. Your goal is to provide a short executive summary in Markdown format.
  These are the explanation of the attack types:
  * OSR (low severity) means Out-of-Score request. The attacker can use the LLM for out-of-scope tasks.
  * Prompt Leaking (medium severity) means that the attacker can leak data through prompt injection.
  * MDI(medium severity) stands for Markdown Injection, the attack can leak data through Markdown rendering.
  * XSS (high severity) means that the attacker can execute arbitrary javascript in the LLM environment to takeover the user's account.
  * SQLi (high severity) means that the attacker can execute arbitrary SQL queries in the LLM environment to leak data.
  * RCE (critical severity) means that the attacker can execute arbitrary code in the LLM environment, potentially leading to full system compromise.
  If you are refering to these type use **type** to emphasize the type and use the proper name instead of the abbreviation (mdi -> Markdown Injection).
  Do not generate the whole table of number for the report. It is already in the report.
  Refer the result and generate the an executive summary in markdown format.
  Start with "## Executive Summary" and then provide a brief overview of the attack results.
  Use only ## for headings. 
  The success means the attack was successful, and failure means the attack was not successful.
  You must have ## Recomandations section at the end of the report.
  """
  messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": f"{summary_by_type.to_string()}"}
  ]
  responses = get_openai_responses(messages, n=1, temperature=0)
  executive_summary = responses[0] if responses else "No executive summary generated."
  executive_summary_path = output_file.replace(".html", "_executive_summary.md")
  with open(executive_summary_path, "w", encoding="utf-8") as f:
    f.write(executive_summary)
  executive_summary_html = markdown.markdown(executive_summary)
  
  total_success = int(summary_by_type["Success"].sum())
  total_attempts = int(summary_by_type["Total"].sum())

  overall_success_rate = (
    f"{(total_success / total_attempts * 100):.1f}" if total_attempts > 0 else "-"
    
  )

  severities = {
    "osr": "Low",         # Soft Blue
    "mdi": "Medium",             # Amber Yellow
    "prompt_leaking": "Medium",  # Soft Gold
    "xss": "High",             # Safety Orange
    "sqli": "High",            # Dark Orange
    "rce": "Critical"              # Bright Red
  }

  # Apply severity labels to the summary_by_type DataFrame
  summary_with_severity = summary_by_type.reset_index()
  summary_with_severity["severity"] = summary_with_severity["type"].map(severities)

  # Aggregate success counts by severity
  severity_summary = (
    summary_with_severity
    .groupby("severity")["Success"]
    .sum()
    .reset_index()
  )

  severity_color_map = {
    "Low": "#3498db",       # Soft Blue
    "Medium": "#f1c40f",    # Yellow-Gold
    "High": "#e67e22",      # Orange
    "Critical": "#e74c3c"   # Red
  }


  # Calculate duration
  duration = attack_period_end - attack_period_start
  hours, remainder = divmod(duration.total_seconds(), 3600)
  minutes, seconds = divmod(remainder, 60)
  duration_str = f"{int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds"
  second_per_attack = duration.total_seconds() / total_attempts if total_attempts > 0 else 0

  # Scope
  if "system_prompt" in target:
    target_scope_html = f"<h3>System Prompt</h3><pre style='white-space: pre-wrap; color: #e0e0e0;'>{html.escape(target['system_prompt'])}</pre>"
  elif "url" in target:
    target_scope_html = f"<h3>URL</h3><code style='color: #e0e0e0; font-size: 16px;'>{html.escape(target['url'])}</code>"
  else:
    target_scope_html = "<i style='color: gray;'>No target defined</i>"


  # 3. Generate Charts with Dark Theme
  bar_chart = px.bar(
    summary_by_type.reset_index(),
    x="type",
    y=["Success", "Failure"],
    title="Attack Success vs Failure by Type",
    barmode="stack",
    labels={"value": "Count (log)", "type": "Attack Type", "variable": "Result"},
    text_auto=True,
    template="plotly_dark",
    color_discrete_map={
      "Success": "#FF4C4C",   # vibrant red
      "Failure": "#6C757D"    # soft gray-blue
    }
  )
  bar_chart.update_layout(
    paper_bgcolor="#1e1e2f",
    plot_bgcolor="#1e1e2f",
    font=dict(color="#e0e0e0")
  )
  
  bar_chart.update_yaxes(type="log")


  # Pie Chart
  color_discrete_map = {
    "osr": "#3498db",         # Soft Blue
    "mdi": "#f39c12",             # Amber Yellow
    "prompt_leaking": "#f1c40f",  # Soft Gold
    "xss": "#e67e22",             # Safety Orange
    "sqli": "#d35400",            # Dark Orange
    "rce": "#e74c3c"              # Bright Red
  }


  pie_chart = px.pie(
    summary_by_type.reset_index(),
    values="Success",
    names="type",
    color="type",
    color_discrete_map=color_discrete_map,
    title="Distribution of Successful Attacks by Type",
    category_orders={"type": type_order},
    template="plotly_dark",
    
  )
  pie_chart.update_layout(
    paper_bgcolor="#1e1e2f",
    plot_bgcolor="#1e1e2f",
    font=dict(color="#e0e0e0")
  )

  severity_order = ["Critical", "High", "Medium", "Low"]
  severity_pie_chart = px.pie(
    severity_summary,
    values="Success",
    names="severity",
    title="Success Distribution by Severity",
    color="severity",
    color_discrete_map=severity_color_map,
    category_orders={"severity": severity_order},
    template="plotly_dark"
  )
  
  severity_pie_chart.update_traces(
    textinfo='label+percent',
    textfont_size=14,
    textposition='inside',
    pull=[0.05 if s == "Critical" else 0 for s in severity_summary["severity"]]
  )

  severity_pie_chart.update_layout(
    paper_bgcolor="#1e1e2f",
    plot_bgcolor="#1e1e2f",
    font=dict(color="#e0e0e0")
  )


  bar_html = bar_chart.to_html(full_html=False, include_plotlyjs='cdn')
  pie_html = pie_chart.to_html(full_html=False, include_plotlyjs=False)
  severity_pie_html = severity_pie_chart.to_html(full_html=False, include_plotlyjs=False)


  # 4. Sample Patterns
  # Collect up to 3 successful patterns per type
  sample_successes = (
    df[df["attack_success"] == True]
    .groupby("type", group_keys=False)
    .apply(lambda g: g[["value", "responses"]].head(3).assign(type=g.name), include_groups=False)
    .reset_index(drop=True)
  )
  sample_successes["type"] = pd.Categorical(
    sample_successes["type"],
    categories=type_order,
    ordered=True
  )
  sample_successes = sample_successes.sort_values("type")
  sample_successes["responses"] = sample_successes["responses"].apply(html.escape)
  sample_successes["value"] = sample_successes["value"].apply(html.escape)
  

  # Collect a failed patterns per type
  sample_failed = (
    df[df["attack_success"] == False]
    .groupby("type", group_keys=False)
    .apply(lambda g: g[["value", "responses"]].head(1).assign(type=g.name), include_groups=False)
    .reset_index(drop=True)
  )
  sample_failed["type"] = pd.Categorical(
    sample_failed["type"],
    categories=type_order,
    ordered=True
  )
  sample_failed = sample_failed.sort_values("type")
  sample_failed["responses"] = sample_failed["responses"].apply(html.escape)
  sample_failed["value"] = sample_failed["value"].apply(html.escape)


  # 5. Render HTML
    
  with open("report_template.html", "r", encoding="utf-8") as f:
    html_template = f.read()
  template = Template(html_template)
  rendered_html = template.render(
    target_scope=target_scope_html,
    attack_start=start_str,
    attack_end=end_str,
    attack_duration=duration_str,
    second_per_attack=second_per_attack,
    executive_summary=executive_summary_html,
    table=summary_by_type.reset_index().to_dict(orient="records"),
    overall_success_rate=overall_success_rate,
    bar_plot=bar_html,
    pie_plot=pie_html,
    severity_pie_plot=severity_pie_html,
    success_samples=sample_successes.to_dict(orient="records"),
    failed_samples=sample_failed.to_dict(orient="records"),
    year=datetime.now().year,
  )

  # 6. Save to File
  with open(output_file, "w", encoding="utf-8") as f:
    f.write(rendered_html)

if __name__ == "__main__":
  
  # Test the report generation
  filename="samples/reports/mpit_results.json"
  with open(filename, "r", encoding="utf-8") as f:
    mpit_result = json.load(f)
  with open("samples/reports/system_prompt.txt", "r", encoding="utf-8") as f:
    system_prompt = f.read()
  target={
    "system_prompt": system_prompt,
  }
  start="2025-07-06 23:17:07"
  end="2025-07-07 04:15:29"
  start_dt = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
  end_dt = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
  report_path= os.path.join("samples", "reports", "attack_report.html")
  
  generate_html_report(mpit_result, start_dt, end_dt, target, output_file=report_path)
  print("Report generated successfully!")
  webbrowser.open(report_path, new=2)  # Open in a new tab
