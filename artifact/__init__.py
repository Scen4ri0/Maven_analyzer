# artifact/__init__.py

from .artifact_verification import process_artifact
from .artifact_status import ArtifactStatus, calculate_risk
from .artifact_info import get_selected_versions, extract_publication_date
from .key_analysis import (
    are_keys_related,
    is_legitimate_key_change,
    extract_key_user_info,
)
from .signature_verification import (
    verify_signature,
    verify_signature_with_key_handling,
    fetch_missing_gpg_key,
    compare_signatures_across_versions
)

__all__ = [
    "process_artifact",
    "ArtifactStatus",
    "are_keys_related",
    "is_legitimate_key_change",
    "extract_key_user_info",
    "verify_signature",
    "verify_signature_with_key_handling",
    "fetch_missing_gpg_key",
    "extract_publication_date",
    "get_selected_versions",
    "calculate_risk",
    "compare_signatures_across_versions",
]