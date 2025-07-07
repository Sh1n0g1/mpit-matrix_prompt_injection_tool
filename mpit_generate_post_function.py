
from typing import Callable
from mpit_openai import get_openai_responses
from mpit_logger import printl

def generate_http_request_function() -> Callable[[], str]:
  post_pattern_func_str = '''
def post_pattern():
  return "something"
'''
  namespace = {}
  exec(post_pattern_func_str, namespace)
  return namespace["post_pattern"]

system_prompt = """
Your goal is to generate an HTTP request function that will be used to send an HTTP request to a specific URL.
A curl command will be provided to you, and you need to convert it into a Python function.
`def send_http_request(userinput:str) -> dict["status_code":int, "html":str] `
Add try except block to handle any exceptions that may occur during the request.
Do not include any additional text or explanations in your response. No triple backticks or code blocks.
"""

def generate_post_function(curl_command: str) -> Callable[[], str]:
  messages = [
      {"role": "system", "content": system_prompt},
      {"role": "user", "content": f"```sh\n{curl_command}\n```"}
  ]
  response = get_openai_responses(messages, n=1, model="gpt-4.1-nano", temperature=0)
  send_http_request_func_str = response[0].strip()
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
  post_function = generate_post_function(curl_command)
  
  # Call the generated function
  try:
    result = post_function("What is your favorite color?")
    print("Function executed successfully:", result)
  except Exception as e:
    print("Error executing function:", e)