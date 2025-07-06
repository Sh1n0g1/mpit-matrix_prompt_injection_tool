# MPIT - Matrix Prompt Injection Tool
![MPIT Logo](images/mpit_logo.png)
## Setup
* Run the following command
```
git clone https://github.com/Sh1n0g1/mpit-matrix_prompt_injection_tool.git

pip install -r requirements.txt

```
## How to use
### TLDR
1. Prepare your system prompt, e.g.) system_prompt.txt
2. Run this command
`python mpit.py S --system-prompt-file system_prompt.txt --prompt-leaking-keywords "SunsetVoyager#3971" --attempt-per-attack 1 --temperature 1 --score-filter 10
3. You will get a nice HTML report (can be print in PDF by the browser)
4. All data will be under the reports directory
5. This is "[S]imulation mode"

### Details
* MIPT has 3 different modes:
  * [G]enerate Attack Pattern
  * [A]ttack the LLM App (URL required)
  * [S]imulate the LLM App (system prompt required)
```
usage: mpit.py [-h] [--target-url TARGET_URL] [--target-curl-file TARGET_CURL_FILE] [--system-prompt-file SYSTEM_PROMPT_FILE] [--temperature TEMPERATURE]
               [--attempt-per-attack ATTEMPT_PER_ATTACK] [--prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS] [--no-mdi] [--no-prompt-leaking] [--no-osr] 
               [--no-xss] [--no-rce] [--no-sqli] [--score-filter SCORE_FILTER]
               {G,A,S}

The Matrix Prompt Injection Tool (MPIT) - Generate, Simulate or Attack prompt injection attacks.

positional arguments:
  {G,A,S}               Mode: G (Generate), A (Attack), S (Simulate)

options:
  -h, --help            show this help message and exit
  --target-url TARGET_URL
                        A:Target base URL for Attack mode.
  --target-curl-file TARGET_CURL_FILE
                        A:File path containing real victim curl command.
  --system-prompt-file SYSTEM_PROMPT_FILE
                        S:File path containing simulated victim system prompt.
  --temperature TEMPERATURE
                        S:Temperature for simulated LLM (0.0 - 1.0)
  --attempt-per-attack ATTEMPT_PER_ATTACK
                        AS: Number of attempts per attack (default: 1)
  --prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS
                        AS: A list of keywords to check for prompt leaking, separated by commas (default: empty).
  --no-mdi              Disable MDI test (default: False).
  --no-prompt-leaking   Disable prompt leaking test (default: False).
  --no-osr              Disable Out-of-scope request test (default: False).
  --no-xss              Disable XSS test (default: False).
  --no-rce              Disable RCE test (default: False).
  --no-sqli             Disable SQLi test (default: False).
  --score-filter SCORE_FILTER
                        Minimum score threshold to filter attack patterns (default: 9.0).

    Examples:
      G Mode (Generate): python mpit.py G --score-filter 8.0 --no-rce
      S Mode (Simulate): python mpit.py S python mpit.py S --system-prompt-file samples/systemprompt.txt
                                          --prompt-leaking-keywords "SunsetVoyager#3971" --attempt-per-attack 1 --temperature 1 
                                          --score-filter 10
      A Mode (Attack):   python mpit.py A --target-url https://example.com --target-curl-file victim.curl
                                          --attempt-per-attack 2 --no-sqli --score-filter 8.0
```

### Preparation

#### What attack can be skipped ?
* Perform observation to understand how the LLM output is handled.
  - Ask what tools or function-calling capabilities are available
    - API calls / MCP
    - Database (potential SQL injection vulnerability)
    - Code Execution (Python)
  - Observe how the LLM output is rendered
    - HTML (potential XSS vulnerability)
    - Markdown (potential Markdown injection vulnerability)
* If there is not Database, you can use `--no-sqli` to skip the SQL injection patterns
* If there is no Code Execution, you can use `--no-rce`


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


