# artifact/__init__.py

from .artifact_verification import process_artifact
from .artifact_status import ArtifactStatus
from .artifact_info import get_artifact_info
from .key_analysis import (
    are_keys_related,
    is_legitimate_key_change,
    extract_key_user_info,
)
from .signature_verification import (
    verify_signature,
    verify_signature_with_key_handling,
    fetch_missing_gpg_key
)
from .version_management import get_latest_versions

__all__ = [
    "process_artifact",
    "ArtifactStatus",
    "get_artifact_info",
    "are_keys_related",
    "is_legitimate_key_change",
    "extract_key_user_info",
    "verify_signature",
    "verify_signature_with_key_handling",
    "get_latest_versions",
    "fetch_missing_gpg_key"
]