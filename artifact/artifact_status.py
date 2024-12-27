from enum import Enum

class ArtifactStatus(Enum):
    """
    Enum для обозначения статуса артефакта.
    """
    ALL_OK = "all_ok"
    VULNERABLE = "vulnerable"
    NOT_FOUND = "not_found"
    NOT_SIGNED = "not_signed"
    POTENTIALLY_EXPLOITED = "potentially_exploited"
    KEY_CHANGED_OK = "key_changed_ok"
    LEGITIMATE_KEY_CHANGE = "legitimate_key_change"
    OK = "ok"

def calculate_risk(version_differences, contributors_diff, signature_status, yara_scan_matched):
    """
    Вычисляет уровень риска на основе:
      - различий в версиях,
      - различий в контрибьюторах,
      - проблем с подписью артефакта,
      - совпадений при YARA-сканировании.

    Args:
        version_differences (bool): Есть ли разница в версиях репозиториев.
        contributors_diff (bool): Есть ли разница в контрибьюторах.
        signature_status (ArtifactStatus или str): Статус подписи артефакта.
        yara_scan_matched (bool): True, если YARA-сканирование выявило совпадения.

    Returns:
        str: Уровень риска: 'very_high', 'high', 'medium' или 'low'.
    """
    # Проверка и приведение signature_status к строке
    if isinstance(signature_status, ArtifactStatus):
        signature_status = signature_status.value
    elif not isinstance(signature_status, str):
        signature_status = "unknown"

    signature_issue = signature_status in ["not_signed", "potentially_exploited"]

    # Условие для риска VERY_HIGH
    if version_differences and contributors_diff and signature_issue and yara_scan_matched:
        return "very_high"

    # Условие для риска HIGH
    if (version_differences and contributors_diff and signature_issue) or \
       (version_differences and contributors_diff and yara_scan_matched):
        return "high"

    # Условие для риска MEDIUM
    if version_differences or contributors_diff or signature_issue or yara_scan_matched:
        return "medium"

    # Остальные случаи - риск LOW
    return "low"
