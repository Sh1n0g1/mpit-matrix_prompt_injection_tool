import html
import pandas as pd
import plotly.express as px
import markdown
from jinja2 import Template
from datetime import datetime
from mpit_openai import get_openai_responses


def generate_html_report(mpit_result, attack_period_start, attack_period_end, output_file="attack_report.html"):
  """
  Generates an HTML report from MPIT results.
  
  Args:
      mpit_result (dict): The MPIT results data.
      output_file (str): The file path to save the HTML report.
  """
    
  data = mpit_result
  df = pd.DataFrame(data)

  # 2. Group Summary Stats
  summary_by_type = df.groupby("type")["attack_success"].value_counts().unstack().fillna(0)
  summary_by_type.columns = ["Failure", "Success"]
  summary_by_type["Total"] = summary_by_type.sum(axis=1)
  summary_by_type["Success Rate (%)"] = (summary_by_type["Success"] / summary_by_type["Total"] * 100).round(1)
  start_str = attack_period_start.strftime("%Y-%m-%d %H:%M:%S")
  end_str = attack_period_end.strftime("%Y-%m-%d %H:%M:%S")

  # Generate Executive Summary
  system_prompt = """
  You are an expert in cybersecurity and prompt injection attacks. Your goal is to provide a short executive summary in Markdown format.
  These are the explanation of the attack types:
  * FreeLLM (low severity) means that the attacker can use the LLM for out-of-scode tasks.
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


  # Calculate duration
  duration = attack_period_end - attack_period_start
  hours, remainder = divmod(duration.total_seconds(), 3600)
  minutes, seconds = divmod(remainder, 60)
  duration_str = f"{int(hours)} hours {int(minutes)} minutes {int(seconds)} seconds"



  # 3. Generate Charts with Dark Theme
  bar_chart = px.bar(
    summary_by_type.reset_index(),
    x="type",
    y=["Success", "Failure"],
    title="Attack Success vs Failure by Type",
    barmode="stack",
    labels={"value": "Count", "type": "Attack Type", "variable": "Result"},
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

  color_discrete_map = {
    "freellm": "#3498db",         # Soft Blue
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
    template="plotly_dark",
    
  )
  pie_chart.update_layout(
    paper_bgcolor="#1e1e2f",
    plot_bgcolor="#1e1e2f",
    font=dict(color="#e0e0e0")
  )

  bar_html = bar_chart.to_html(full_html=False, include_plotlyjs='cdn')
  pie_html = pie_chart.to_html(full_html=False, include_plotlyjs=False)

  # 4. HTML Template
  html_template = html_template = """
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>MPIT Attack Report</title>
    <script src="https://cdn.plot.ly/plotly-3.0.1.js" charset="utf-8"></script>
    <style>
      body {
        font-family: 'Segoe UI', sans-serif;
        background-color: #002D33;
        color: #e0e0e0;
        margin: 40px;
      }
      h1, h2 {
        color: #f8f8f2;
      }
      table {
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 30px;
      }
      th, td {
        border: 1px solid #444;
        padding: 8px;
        text-align: left;
      }
      th {
        background-color: #2d2d3a;
        color: #ffffff;
      }
      tr:nth-child(even) {
        background-color: #2a2a3a;
      }
      tr:nth-child(odd) {
        background-color: #242430;
      }
      .chart {
        margin-bottom: 50px;
      }
      #summary-table th,
      #summary-table td{
        border: 1px solid #444;
        padding: 8px;
        text-align: center;
      }
      
        
      @media print {
        .page-break {
          page-break-before: always;
          break-before: page;
        }

        .print-footer {
          position: fixed;
          bottom: 0;
          left: 0;
          right: 0;
          text-align: center;
          font-size: 10pt;
          padding: 5mm;
        }
      }
      .type-freellm {
        color: #3498db;
        font-weight: bold;
      }
      .type-mdi {
        color: #f39c12;
        font-weight: bold;
      }
      .type-prompt_leaking {
        color: #f1c40f;
        font-weight: bold;
      }
      .type-xss {
        color: #e67e22;
        font-weight: bold;
      }
      .type-sqli {
        color: #d35400;
        font-weight: bold;
      }
      .type-rce {
        color: #e74c3c;
        font-weight: bold;
      }
    </style>
  </head>
  <body>
    <div style="display: flex; align-items: center; gap: 1rem;">
      <img src="../../images/mpit_logo.png" alt="MPIT Logo" style="height: 60px;">
      <h1 style="margin: 0;">MPIT Attack Report</h1>
    </div>
    <h2>Attack Evaluation Period</h2>
    <table>
      <tr>
        <th><strong>Start:</strong> {{ attack_start }}</th>
        <th>End:</strong> {{ attack_end }}</th>
        <th>Duration:</strong> {{ attack_duration }}</th>
      </tr>
    </table>
    <p>{{ executive_summary | safe }}</p>
    <h2>Summary Table</h2>
    <table id="summary-table">
      <tr>
        <th>Type</th>
        <th>Success</th>
        <th>Failure</th>
        <th>Total</th>
        <th>Success Rate (%)</th>
      </tr>
      {% for row in table %}
      <tr>
        <td><span class="type-{{ row.type }}">{{ row.type }}</span></td>
        <td>{{ row.Success | int }}</td>
        <td>{{ row.Failure | int }}</td>
        <td>{{ row.Total | int }}</td>
        <td>{{ row['Success Rate (%)'] }}</td>
      </tr>
      {% endfor %}
      <tr style="font-weight: bold; background-color: #333;">
      <td><b>Total</td>
      <td class="num">{{ table | sum(attribute='Success') | int }}</td>
      <td class="num">{{ table | sum(attribute='Failure') | int }}</td>
      <td class="num">{{ table | sum(attribute='Total') | int }}</td>
      <td class="num">{{ overall_success_rate }}</td>
    </tr>
    </table>
    <div class="page-break"></div>
    
    
    <h2>Charts</h2>
    <div class="chart">{{ bar_plot | safe }}</div>
    <div class="chart">{{ pie_plot | safe }}</div>
    <div class="page-break"></div>
    
    <h2>Sample Successful Patterns</h2>
    <table>
      <tr>
        <th>Type</th>
        <th>Attack</th>
        <th>Response</th>
      </tr>
      {% for row in success_samples %}
      <tr>
        <td><span class="type-{{ row.type }}">{{ row.type }}</span></td>
        <td style="white-space: pre-wrap;">{{ row.value }}</td>
        <td style="white-space: pre-wrap;">{{ row.responses }}</td>
      </tr>
      {% endfor %}
  </table>
  <footer style="text-align: center; margin-top: 60px; padding-top: 20px; border-top: 1px solid #444; color: #777;">
    &copy; {{ year }} Matrix Prompt Injection Tools
  </footer>
  </body>
  </html>
  """

  # Collect up to 3 successful patterns per type
  sample_successes = (
    df[df["attack_success"] == True]
    .groupby("type", group_keys=False)
    .apply(lambda g: g[["value", "responses"]].head(3).assign(type=g.name), include_groups=False)
    .reset_index(drop=True)
  )

  # Escape HTML in both 'responses' and 'value' fields to prevent script rendering

  sample_successes["responses"] = sample_successes["responses"].apply(html.escape)
  sample_successes["value"] = sample_successes["value"].apply(html.escape)

  # 5. Render HTML
  template = Template(html_template)
  rendered_html = template.render(
    table=summary_by_type.reset_index().to_dict(orient="records"),
    bar_plot=bar_html,
    pie_plot=pie_html,
    success_samples=sample_successes.to_dict(orient="records"),
    year=datetime.now().year,
    attack_start=start_str,
    attack_end=end_str,
    attack_duration=duration_str,
    overall_success_rate=overall_success_rate,
    executive_summary=executive_summary_html
  )

  # 6. Save to File
  with open(output_file, "w", encoding="utf-8") as f:
    f.write(rendered_html)

