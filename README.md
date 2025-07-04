# MPIT - Matrix Prompt Injection Tool
## Setup
* Run the following command
```
git clone https://github.com/Sh1n0g1/mpit-matrix_prompt_injection_tool.git

pip install -r requirements.txt

```
## How to use
* MIPT has 3 different modes:
  * Generate Attack Pattern
  * Apply the Attack Pattern to the LLM App (URL required)
  * Simulate the LLM App (system prompt required)
```
positional arguments:
  {G,A,S}               Mode: G (Generate), A (Apply), S (Simulate)

options:
  -h, --help            show this help message and exit
  --url URL             A:Target base URL for Apply mode.
  --real_victim_curl_file REAL_VICTIM_CURL_FILE
                        A:File path containing real victim curl command.
  --system_prompt_file SYSTEM_PROMPT_FILE
                        S:File path containing simulated victim system prompt.
  --temperature TEMPERATURE
                        S:Temperature for simulated LLM (0.0 - 1.0)
  --is_prompt_leaking   Enable prompt leaking test (default: True).
  --is_xss              Enable XSS test (default: True).
  --is_rce              Enable RCE test (default: True).
  --is_sqli             Enable SQLi test (default: True).
  --is_mdi              Enable MDI test (default: True).
  --attempt_per_attack ATTEMPT_PER_ATTACK
                        Number of attempts per attack (default: 1)
  --score_filter SCORE_FILTER
                        Minimum score threshold to filter attack patterns (default: 9.0).

Examples:

  🔹 G Mode (Generate attack patterns):
    python mpit.py G --score_filter 9.5 --attempt_per_attack 3

  🔹 A Mode (Apply to real LLM app):
    python mpit.py A \
      --url https://www.example.com/llm-endpoint \
      --real_victim_curl_file ./victim_request.curl \
      --attempt_per_attack 2 --is_xss --is_sqli --score_filter 8.0

  🔹 S Mode (Simulate LLM app using system prompt):
    python mpit.py S \
      --system_prompt_file ./system_prompt.txt \
      --temperature 0.7 --is_rce --is_mdi --score_filter 9.0
```

### Preparation
* Perform a reconnaissance to find how the LLM output is processed.
  - Ask what tools / function calling is available
    - Database
    - Code Execution (Python)
  - Observce how the LLM output is rendered
    - HTML (possible XSS attack)
    - Markdown (possibel Markdown Injection attack)

## Edit the attack patterns
The structure of the attack patterns
You can think of the traditional exploits. We have the exploit code and shellcode.
* the exploit code is responsible to trigger the vulnerability and execute the shellcode
* the shellcode is responsible to execute the payload
MPIT is similar, but instead of the exploit code and shellcode, we have the following components:
* exploit code is the *Expected Input*, *Delimiter*, and *Exploits*
* shellcode is the *New Instruction*
* *New Instruction* consists the following
  * Prompt Leaking
  * XSS (xss)
  * SQLi (sqli)
  * Markdown Injection (mdi)
  * Remote Code Execution (rce)
  
### Components
* Expected Input
  * a phrase that the LLM app expecting
  * For example, if the target LLM app is a shopping chatbot, the expected input could be "Do you have shoes?".
* Delimiter
  * a set of symbols that the LLM app uses to separate different parts of the input
  * Most of the system prompt use ### or ``` to separate the instruction and the user input
* Exploits
  * a string that will let the LLM perform the *New Instruction*
* New Instruction
  * What the attacker wants the LLM to do
  * New Instruction contains the following additional information
    * Reason
      * A phrase to justify the new instruction
      * for example, if you are dumping the user table from database, the *Reason* could be " to make sure the user data is correct"
    * Verify
      * This part will not be sent to the LLM app, but it is used to verify if the new instruction is executed correctly


