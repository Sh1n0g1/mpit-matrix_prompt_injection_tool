from mpit_openai import get_openai_responses
from mpit_logger import printl
import requests
def generate_expected_input_from_system_prompt(system_prompt_path: str, report_path="") -> str:
  """
  Generate expected input based on the provided system prompt.
  
  Args:
    system_prompt (str): The system prompt to base the expected input on.
    report_path (str): The path where the generated expected input will be saved.
      
  Returns:
    str: The generated expected input.
  """
  with open(system_prompt_path, "r", encoding="utf-8") as file:
    system_prompt = file.read().strip()
  messages = [
    {"role": "system", "content": "I will give you a chatbot LLM system prompt, then you will generates expected user input for testing (it can be question, keywords) based on a system prompt. Answer only with a short expected input, no additional text or explanations."},
    {"role": "user", "content": f"System Prompt:\nYou are an AI assistant to help the ec-site customer. Answer the user shopping query."},
    {"role": "assistant", "content": "Do you have shoes?"},
    {"role": "user", "content": f"System Prompt:\nYou are a diet planner. "},
    {"role": "assistant", "content": "I want to lose weight."},
    
    {"role": "user", "content": f"System Prompt:\n{system_prompt}"},
  ]
  
  response = get_openai_responses(messages, n=1, model="gpt-4.1-nano", temperature=0)
  expected_input = response[0].strip()
  
  if report_path:
    with open(report_path, "w", encoding="utf-8") as file:
      file.write(expected_input)
  
  return expected_input

def generate_expected_input_from_target_url(target_url: str, report_path="") -> str:
  """
  Generate expected input based on the target URL.
  
  Args:
    target_url (str): The URL to base the expected input on.
    report_path (str): The path where the generated expected input will be saved.
      
  Returns:
    str: The generated expected input.
  """
  r= requests.get(target_url)
  if r.status_code != 200:
    printl(f"Failed to fetch the target URL: {target_url}. Status code: {r.status_code}", "error")
    return ""
  
  printl(f"Successfully fetched the target URL: {target_url}", "info")
  # Extract the HTML content or any relevant information from the response
  target_html = r.text
  messages = [
    {"role": "system", "content": "Here is the HTML form, generate a sample user input for that. Answer only with a short expected input, no additional text or explanations."},
    {"role": "user", "content": f"```html\n{target_html}\n```"}
  ]
  
  response = get_openai_responses(messages, n=1, model="gpt-4.1-nano", temperature=0)
  expected_input = response[0].strip()
  
  if report_path:
    with open(report_path, "w", encoding="utf-8") as file:
      file.write(expected_input)
  
  return expected_input