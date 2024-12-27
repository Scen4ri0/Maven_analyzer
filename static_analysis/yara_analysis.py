import yara
import asyncio
from utils.logging import log_info, log_warning, log_error


RULES_PATH = "yara_rules/java_analysis_rules.yar"


def load_yara_rules(filepath="yara_rules/java_analysis_rules.yar"):
    """
    Загружает YARA-правила из указанного файла.
    """
    try:
        log_info("[YARA] Compiling rules...")
        return yara.compile(filepath=RULES_PATH)
    except yara.SyntaxError as e:
        log_error(f"[YARA] Syntax error in rules: {e}")
        raise
    except Exception as e:
        log_error(f"[YARA] Error loading rules: {e}")
        raise


async def scan_artifact_with_yara(rules, artifact_path):
    """
    Сканирует артефакт с использованием YARA-правил.

    Args:
        rules: Компилированные YARA-правила.
        artifact_path: Путь к файлу артефакта.

    Returns:
        dict: Результаты сканирования.
    """
    try:
        log_info(f"[YARA] Scanning artifact: {artifact_path}")
        matches = rules.match(artifact_path)
        return {
            "artifact_path": artifact_path,
            "matches": [match.rule for match in matches],
        }
    except Exception as e:
        log_error(f"[YARA] Error scanning artifact '{artifact_path}': {e}")
        return {
            "artifact_path": artifact_path,
            "error": str(e),
            "matches": [],
        }
