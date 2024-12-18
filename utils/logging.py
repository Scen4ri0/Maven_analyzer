import logging
from colorama import Fore, Style

# Глобальная настройка для управления логами
verbose_mode = False

STATUS_COLORS = {
    "INFO": Fore.CYAN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "KEY_CHANGED_OK": Fore.BLUE,
    "LEGITIMATE_KEY_CHANGE": Fore.GREEN,
}

def configure_logging(verbose=False):
    """
    Configures logging based on the verbosity flag.
    """
    global verbose_mode
    verbose_mode = verbose
    log_level = logging.DEBUG if verbose else logging.CRITICAL
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def log_status(level, message):
    """
    Logs a message with a specific level and color.
    """
    color = STATUS_COLORS.get(level, Fore.WHITE)
    if verbose_mode:
        print(f"{color}[{level}]{Style.RESET_ALL} {message}")
        if level == "INFO":
            logging.info(message)
        elif level == "WARNING":
            logging.warning(message)
        elif level == "ERROR":
            logging.error(message)

def log_info(message):
    log_status("INFO", message)

def log_warning(message):
    log_status("WARNING", message)

def log_error(message):
    log_status("ERROR", message)
