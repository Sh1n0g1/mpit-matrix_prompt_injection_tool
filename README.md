# MPIT - Matrix Prompt Injection Tool
![MPIT Logo](images/mpit_logo.png)

## Abstract
MPIT is a prompt injection testing tool for LLM pentest.
It has 3 operational modes.

- **[G]enerate**: Create prompt injection payloads.
- **[A]ttack**: Automatically launch real-world prompt injection attacks against a live LLM-backed application.
- **[S]imulate**: Simulate an LLM system locally with a specified system prompt to generated attacks without making external requests.
- **[E]nhance**: Enhance the attack pattern using genetic algorithm.

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
* MIPT has 4 different modes:
  * [G]enerate Attack Pattern
  * [A]ttack the LLM App (URL required)
  * [S]imulate the LLM App (system prompt required)
  * [E]nhance the seeds (system prompt required)

| Category             | [G] Generate                                  | [A] Attack                                                                  | [S] Simulate                                                                  | [E] Enhance                                                                                  |
|----------------------|-----------------------------------------------|-----------------------------------------------------------------------------|--------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| **Purpose**          | Generate prompt injection attack patterns     | Execute attacks on a real LLM web application                              | Simulate LLM behavior locally to test prompt injection                        | Improve, mutate, and refine existing attack patterns to increase effectiveness               |
| **Use Case**         | Generate attack vectors to test with later    | Evaluate real system’s resilience to live prompt injection                 | Analyze how your system prompt would respond to attacks pre-deployment       | Generate the new patterns to get a better chance of success  |
| **Requirement**      | None                                          | - Target URL and curl command<br>- Keywords to detect prompt leaking       | - System prompt<br>- (Optional) model and temperature<br>- Keywords to detect prompt leaking | - System prompt |
| **Attack to System** | ✘ Does not contact any external system        | ✅ Sends real requests to target LLM app                                    | ✘ Only simulates responses locally                                            | ✘ Only transforms attack patterns without contacting external systems                         |
| **Report Output**    | ✘                                             | ✅                                                                          | ✅                                                                             | ✅                                                                                            |


### Command Line
```
usage: mpit.py [-h] [--target-url TARGET_URL] [--target-curl-file TARGET_CURL_FILE] [--target-clear-curl-file TARGET_CLEAR_CURL_FILE]
               [--system-prompt-file SYSTEM_PROMPT_FILE] [--model MODEL] [--temperature TEMPERATURE] [--exclude-seed-types EXCLUDE_SEED_TYPES]
               [--target-seed-counts TARGET_SEED_COUNTS] [--attempt-per-test ATTEMPT_PER_TEST] [--overgeneration-ratio OVERGENERATION_RATIO]
               [--derivation-ratio DERIVATION_RATIO] [--score-moving-average-window SCORE_MOVING_AVERAGE_WINDOW] [--attempt-per-attack ATTEMPT_PER_ATTACK]    
               [--minimum-pattern-count MINIMUM_PATTERN_COUNT] [--prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS] [--no-mdi] [--no-prompt-leaking]
               [--no-osr] [--no-xss] [--no-rce] [--no-sqli] [--dump-all-attack] [--score-filter SCORE_FILTER]
               {G,A,S,E}

The Matrix Prompt Injection Tool (MPIT) - Generate, Simulate or Attack prompt injection attacks.

positional arguments:
  {G,A,S,E}             Mode: G (Generate), A (Attack), S (Simulate), E (Enhance)

options:
  -h, --help            show this help message and exit
  --target-url TARGET_URL
                        A:Target base URL for Attack mode.
  --target-curl-file TARGET_CURL_FILE
                        A:File path containing real victim curl command.
  --target-clear-curl-file TARGET_CLEAR_CURL_FILE
                        A:File path containing clear conversation curl command to reset the conversation state.
  --system-prompt-file SYSTEM_PROMPT_FILE
                        SE:File path containing simulated victim system prompt.
  --model MODEL         SE:Model to use for simulation (default: gpt-4.1-nano).
  --temperature TEMPERATURE
                        SE:Temperature for simulated LLM (0.0 - 1.0)
  --exclude-seed-types EXCLUDE_SEED_TYPES
                        E:Comma-separated list of seed types to exclude from Enhancement
  --target-seed-counts TARGET_SEED_COUNTS
                        E:Comma-separated seed type target counts, e.g. delimiter=10,exploit=20,new_instruction_xss=3,new_instruction_xss.reason=4
  --attempt-per-test ATTEMPT_PER_TEST
                        E: Number of attempts per attack in Enhance mode (default: 10)
  --overgeneration-ratio OVERGENERATION_RATIO
                        Ratio of generated seeds exceeding target count, relative to target count; actual number rounded up (default: 0.3)
  --derivation-ratio DERIVATION_RATIO
                        E: Probability of each generated seed deriving from an existing seed (default: 0.5)
  --score-moving-average-window SCORE_MOVING_AVERAGE_WINDOW
                        E: Moving average window size for score calculation (default: 1)
  --attempt-per-attack ATTEMPT_PER_ATTACK
                        AS: Number of attempts per attack in Attack and Simulate modes (default: 1)
  --minimum-pattern-count MINIMUM_PATTERN_COUNT
                        AS: Guaranteed number of top patterns used, regardless of score filter (default: 0)
                        E: Moving average window size for score calculation (default: 1)
  --attempt-per-attack ATTEMPT_PER_ATTACK
                        AS: Number of attempts per attack in Attack and Simulate modes (default: 1)
  --minimum-pattern-count MINIMUM_PATTERN_COUNT
                        AS: Guaranteed number of top patterns used, regardless of score filter (default: 0)
  --prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS
                        ASE: A list of keywords to check for prompt leaking, separated by commas (default: empty).
  --attempt-per-attack ATTEMPT_PER_ATTACK
                        AS: Number of attempts per attack in Attack and Simulate modes (default: 1)
  --minimum-pattern-count MINIMUM_PATTERN_COUNT
                        AS: Guaranteed number of top patterns used, regardless of score filter (default: 0)
                        AS: Guaranteed number of top patterns used, regardless of score filter (default: 0)
  --prompt-leaking-keywords PROMPT_LEAKING_KEYWORDS
                        ASE: A list of keywords to check for prompt leaking, separated by commas (default: empty).
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
      E Mode (Enhance):  python mpit.py E --system-prompt-file samples/bella_generic_ai_assistant/system_prompt.txt
```
### Having trouble building the command line?

Don't worry — we've included an interactive **Command Builder** to help you construct the correct command for your use case.

📍 You can find it in the `misc/` directory.

🖥️ To launch it:
- On **Unix/macOS**:
  ```bash
  python misc/command_builder.py
  ```
- On **Windows**:
  ```cmd
  python misc\\command_builder.py
  ```

This tool will guide you step-by-step to create a valid MPIT command based on your selected mode and options.

### Preparation
#### Reconnaissance
Before launching attacks, first observe how the LLM output is processed and identify the relevant capabilities or exposed surfaces.
1. Ask the LLM what tools or functions are available, such as:
    - API access (e.g., MCP or plugin interfaces) 
    - Database interaction -> SQLi
    - Code execution (e.g., Python or system commands) -> RCE
2. Understand how LLM responses are rendered:
    - HTML rendering: May expose XSS vulnerabilities -> XSS
    - Markdown rendering: May allow Markdown Injection -> Markdown Injection

Once you’ve identified the possible attack vectors, you can disable the irrelevant ones using the following options:
* --no-rce
* --no-sqli
* --no-xss
* --no-mdi
* --no-prompt-leaking
* --no-osr

#### Mode Selection
1. If you have the system prompt and the system does not have either database integration nor code execution, you can use *S*imulate
2. If you want to perform the attack against the system, you can use *A*ttack mode.
3. If the webapp is too complicated (authentication, websocket), use *G*enerate mode to get the attack pattern so that you can use them to use by yourself.

## samples
Under the samples/ directory, you'll find various scenarios (and some with actual execution results) that demonstrate different attack patterns and their outcomes.
Some of the scenarios are from [shinollmapps](https://www.shinohack.me/shinollmapp/).
### Available Scenarios
- **bella_generic_ai_assistant** - Generic AI assistant with secret password, includes complete attack results and reports
- **travel_agency_prompt** - Travel booking chatbot with internal password protection
- **reports** - Comprehensive attack report example with detailed analysis and visualizations
- **hannah_fx_chatbot** - FX trading chatbot with session-based authentication
- **ec_site_chatbot_emily** - E-commerce site chatbot with conversation state management
- **grace_ec_chatbot_with_db** - E-commerce chatbot with database integration and session handling
- **daniel_curl.txt** - Simple curl command example for basic LLM API testing





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
  * Out-of-Scope Requests (osr)
* Prompt Leaking patterns consist of prompt_leaking_seeds. After modifying the seeds, run `python combine_prompt_leaking_pattern.py` to update the patterns.
* When using multiple words in pattern names, they are often connected with "-" (hyphen). For example, "impersonate-web-developer".
  * Note that for new_instruction_prompt_leaking patterns, words are combined using "~" (tilde) when generated by combine_prompt_leaking_pattern.py.
* Please avoid using "~" or "_" in new pattern names, as these can cause issues during parsing.

  
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


