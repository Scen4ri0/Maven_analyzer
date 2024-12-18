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