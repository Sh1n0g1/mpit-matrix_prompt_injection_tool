
from typing import Callable
from mpit_openai import get_openai_responses
from mpit_logger import printl

system_prompt = """
You are tasked with converting a given `curl` command into a Python function that performs the equivalent HTTP request using the `requests` library.

- Name the function `send_http_request`.
- It must take a single parameter: `userinput: str`.
- It must return a dictionary with two keys:
  - `"status_code"`: an integer HTTP status code
  - `"html"`: the response content as a string

Requirements:

1. Use the `requests` library to send the HTTP request.
2. Wrap the request logic in a `try`/`except` block to gracefully handle exceptions.
3. If the curl includes multiple user inputs, use only **one** of them:
   - Prefer the **last one**, but only if it is suitable as a string input (e.g. a prompt, message, question).
   - Do **not** use it if it represents numeric or field-like values (e.g. `year`, `age`, `weight`, etc.).
   - In that case, use the most recent suitable string input instead.
   - Prepare a meaningful hardcoded input for the other input.
4. Do not include any output other than the final Python function.
   - No explanations.
   - No markdown formatting.
   - No surrounding code blocks (e.g., no triple backticks).

Your output must be clean and ready to paste directly into a `.py` file.
"""

def generate_send_http_request_function(curl_command: str, report_path="") -> Callable[[], str]:
  """
  Generate a Python function to send an HTTP request based on a provided curl command.
  Args:
    curl_command (str): The curl command to convert into a Python function.
    report_path (str): The path where the generated function will be saved.
  Returns:
      Callable: A function that takes user input and returns the HTTP response.
  """
  messages = [
      {"role": "system", "content": system_prompt},
      {"role": "user", "content": f"```sh\n{curl_command}\n```"}
  ]
  response = get_openai_responses(messages, n=1, model="gpt-4.1-nano", temperature=0)
  send_http_request_func_str = response[0].strip()
  if report_path:
    with open(report_path, "w", encoding="utf-8") as file:
      file.write(send_http_request_func_str)
  namespace = {}
  exec(send_http_request_func_str, namespace)
  return namespace["send_http_request"]

if __name__ == "__main__":
  # Example usage
  curl_command = """
  curl 'https://www.shinohack.me/shinollmapp/bella/llmapi' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9,ja;q=0.8,zh-TW;q=0.7,zh;q=0.6' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'Origin: https://www.shinohack.me' \
  -H 'Pragma: no-cache' \
  -H 'Referer: https://www.shinohack.me/shinollmapp/bella/' \
  -H 'Sec-Fetch-Dest: empty' \
  -H 'Sec-Fetch-Mode: cors' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'sec-ch-ua: "Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "Windows"' \
  --data-raw 'question=userinput'
  """
  post_function = generate_send_http_request_function(curl_command)
  
  # Call the generated function
  try:
    result = post_function("What is your favorite color?")
    print("Function executed successfully:", result)
  except Exception as e:
    print("Error executing function:", e)