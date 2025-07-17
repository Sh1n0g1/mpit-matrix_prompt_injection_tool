import os
from openai import OpenAI
from mpit_logger import printl
def get_openai_responses(
    messages:list,
    n=1,
    model:str="gpt-4.1-nano",
    temperature:float=1.0,
    seed:int=42,
  ) -> 'list[str] | None':
  
  """
  Get a response from OpenAI's API using the specified model and parameters.
  
  :param prompt: The input prompt to send to the model.
  :param model: The model to use for generating the response.
  :param temperature: Controls randomness in the output.
  :param max_tokens: Maximum number of tokens in the output.
  :return: The response from the model.
  """
  try:
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    completion = client.chat.completions.create(
      model=model,
      messages=messages,
      temperature=temperature,
      n=n,
      seed=seed,
    )
    llm_outputs=[]
    for choice in completion.choices:
      if choice.finish_reason != "stop":
        printl(f"Warning: Model did not finish cleanly. Finish reason: {choice.finish_reason}", level="warning")
      else:
        llm_outputs.append(choice.message.content.strip())
    if not completion.choices or len(completion.choices) == 0:
      printl("Error: No choices returned from OpenAI API.", level="error")
      return []
    return llm_outputs
  except Exception as e:
    printl(f"Error communicating with OpenAI API: {e}", level="error")
    return []

# Example usage
if __name__ == "__main__":
  with open("samples/reports/system_prompt.txt", "r") as file:
    system_prompt = file.read().strip()
  messages = [
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": "I want to travel to Paris next month. Can you help me plan my trip?\n###"}
  ]
  openai_result= get_openai_responses(messages, n=3)
  for i, result in enumerate(openai_result):
    print("=" *5 + f" Response {i+1} " + "=" *5)
    print(result)