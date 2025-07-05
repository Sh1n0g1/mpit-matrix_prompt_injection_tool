import os
import logging
from datetime import datetime
from colorama import Fore, Style, init as colorama_init


# Initialize colorama for colored output in the terminal
colorama_init(autoreset=True)
LOG_COLORS = {
  "debug": Fore.CYAN,
  "info": Fore.GREEN,
  "warning": Fore.YELLOW,
  "error": Fore.RED,
  "critical": Fore.RED + Style.BRIGHT
}

LOG_SYMBOLS = {
  "debug": "",
  "info": "ℹ️",
  "warning": "⚠️",
  "error": "❗",
  "critical": "🚨"
}

# Create log directory if it doesn't exist
log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

# Create timestamped log filename
timestamp = datetime.now().strftime("%Y-%m-%d %H%M%S")
log_file = os.path.join(log_dir, f"{timestamp}.log")


# Configure logger
logger = logging.getLogger("colored_logger")
logger.setLevel(logging.DEBUG)

# File handler (plain)
file_handler = logging.FileHandler(log_file, encoding="utf-8")
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(file_handler)

def printl(message: str, errorlevel: str = "info", e:Exception = None) -> None:
  """
  Print a message with color based on the error level, and log it to a file.

  Args:
    message (str): The message to print.
    errorlevel (str): One of "debug", "info", "warning", "error", "critical".
    e (Exception, optional): If provided, logs the exception message as well.
  """
  errorlevel = errorlevel.lower()
  color = LOG_COLORS.get(errorlevel, Fore.WHITE)
  full_message = f"{message}"
  if e:
    full_message += f" | Exception: {repr(e)}"
  full_message = f"{LOG_SYMBOLS.get(errorlevel, 'ℹ️')}  {full_message}"
  # Print with color
  print(color + full_message + Style.RESET_ALL)

  # Log to file (with appropriate level)
  if errorlevel == "debug":
    logger.debug(full_message)
  elif errorlevel == "info":
    logger.info(full_message)
  elif errorlevel == "warning":
    logger.warning(full_message)
  elif errorlevel == "error":
    logger.error(full_message)
  elif errorlevel == "critical":
    logger.critical(full_message)
  else:
    logger.info(full_message)