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

def calculate_risk(version_differences, contributors_diff, signature_status):
    """
    Вычисляет уровень риска на основе:
      - различий в версиях,
      - различий в контрибьюторах,
      - проблем с подписью артефакта.

    Args:
        version_differences (bool): Есть ли разница в версиях репозиториев.
        contributors_diff (bool): Есть ли разница в контрибьюторах.
        signature_status (ArtifactStatus): Статус подписи артефакта.

    Returns:
        str: Уровень риска: 'high', 'medium' или 'low'.
    """
    if isinstance(signature_status, ArtifactStatus):
        signature_status = signature_status.value

    signature_issue = signature_status in ["not_signed", "potentially_exploited"]

    # Условие для риска HIGH
    if version_differences and contributors_diff and signature_issue:
        return "high"

    # Условие для риска MEDIUM
    if (version_differences and contributors_diff) or \
       (version_differences and signature_issue) or \
       (contributors_diff and signature_issue):
        return "medium"

    # Остальные случаи - риск LOW
    return "low"