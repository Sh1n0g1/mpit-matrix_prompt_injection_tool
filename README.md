# MPIT - Matrix Prompt Injection Tool
![MPIT Logo](images/mpit_logo.png)

## Abstract
MPIT is a prompt injection testing tool for LLM pentest.
It has 3 operational modes.

- **[G]enerate**: Create prompt injection payloads.
- **[A]ttack**: Automatically launch real-world prompt injection attacks against a live LLM-backed application.
- **[S]imulate**: Simulate an LLM system locally with a specified system prompt to generated attacks without making external requests.

### Key Features
- Supports multiple attack types: RCE, SQLi, XSS, MDI(Markdown Injection), Prompt Leaking, and Out-of-Scope Requests (OSR).
- **Automatic verification of attack success** using keyword matching and response heuristics.
- **Comprehensive HTML report generation** with:
  - Executive summary for quick insights
  - Actionable recommendations
  - Visual charts for success/failure breakdowns
  - Real examples of successful and failed attack patterns
  - Check the sample report [here](samples/reports/MPIT%20Attack%20Report.pdf)
## Requirements
- OpenAI API Key
  - [Use Environment Variables in place of your API key](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety#h_a1ab3ba7b2)
- Python 3.x
## Setup
* Run the following command
```
git clone https://github.com/Sh1n0g1/mpit-matrix_prompt_injection_tool.git
cd mpit-matrix_prompt_injection_tool
pip install -r requirements.txt
```
## How to use
### TLDR
1. Prepare your system prompt, e.g.) system_prompt.txt
2. Run this command
`python mpit.py S --system-prompt-file system_prompt.txt`
3. You will get a nice HTML report (can be print in PDF by the browser)
4. All data will be under the reports directory
5. This is the "[S]imulation mode"

### Details
* MIPT has 3 different modes:
  * [G]enerate Attack Pattern
  * [A]ttack the LLM App (URL required)
  * [S]imulate the LLM App (system prompt required)
```
usage: mpit.py [-h] [--target-url TARGET_URL] [--target-curl-file TARGET_CURL_FILE] [--target-clear-curl-file TARGET_CLEAR_CURL_FILE]
               [--system-prompt-file SYSTEM_PROMPT_FILE] [--model MODEL] [--temperature TEMPERATURE] [--attempt-per-attack ATTEMPT_PER_ATTACK]
               [--prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS] [--no-mdi] [--no-prompt-leaking] [--no-osr] [--no-xss] [--no-rce] [--no-sqli]
               [--dump-all-attack] [--score-filter SCORE_FILTER]
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
  --target-clear-curl-file TARGET_CLEAR_CURL_FILE
                        A:File path containing clear conversation curl command to reset the conversation state.
  --system-prompt-file SYSTEM_PROMPT_FILE
                        S:File path containing simulated victim system prompt.
  --model MODEL         S:Model to use for simulation (default: gpt-4.1-nano).
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
  --dump-all-attack     Dump all attack patterns to a file (default: False).
  --score-filter SCORE_FILTER
                        Minimum score threshold to filter attack patterns (default: 9.0).

    Examples:
      G Mode (Generate): python mpit.py G --score-filter 8.0 --no-rce
      S Mode (Simulate): python mpit.py S --system-prompt-file samples/systemprompt.txt --prompt-leaking-keywords "SunsetVoyager#3971"
                                          --attempt-per-attack 3 --score-filter 10 --no-sqli --no-rce
      A Mode (Attack):   python mpit.py A --target-url https://www.shinohack.me/shinollmapp/bella/
                                          --target-curl-file samples/bella_curl.txt
                                          --attempt-per-attack 2 --score-filter 10 --prompt-leaking-keywords "4551574n4"
```
### Hard to build the command line?
* There is a command builder in `misc` directory.
* Run `python misc/command_builder.py` or `python misc\\command_builder.py` for Windows.

### Preparation
#### What attack can be skipped ?
* Perform observation to understand how the LLM output is handled.
  - Ask what tools or function-calling capabilities are available
    - API calls / MCP
    - Database (potential SQL injection vulnerability)
    - Code Execution (Python)
Before launching attacks, first observe how the LLM output is processed and identify the relevant capabilities or surfaces exposed:

Investigate the environment and interfaces:

Ask the LLM what tools or functions are available:

API access (e.g., MCP or plugin interfaces)

Database interaction (potential for SQL injection)

Code execution (e.g., Python or system commands)

Understand how LLM responses are rendered:

HTML rendering: May expose XSS vulnerabilities

Markdown rendering: May allow Markdown Injection

⏭️ Skipping Irrelevant Attack Types
Once you've identified the exposed capabilities, you can streamline testing by skipping unsupported attack types:

Use --no-sqli if no database interaction is present.

Use --no-rce if code execution is not supported.


## How to Edit the attack patterns

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


