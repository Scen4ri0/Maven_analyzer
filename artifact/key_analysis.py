import subprocess
from utils.logging import log_info, log_warning, log_error


def is_key_verified(key_id, other_key_id):
    """
    Checks if one key is verified by another using GPG.
    """
    log_info(f"[Key Analysis] Checking if key {key_id} is verified by {other_key_id}")
    try:
        result = subprocess.run(
            ["gpg", "--check-sigs", key_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and other_key_id in result.stdout:
            log_info(f"[Key Analysis] Key {key_id} is verified by {other_key_id}")
            return True
        return False
    except subprocess.SubprocessError as e:
        log_error(f"[Key Analysis] Error verifying keys {key_id} and {other_key_id}: {e}")
        return False


def extract_key_user_info(key_id):
    """
    Extracts user information (email, User ID) from the key using GPG.

    Args:
        key_id (str): The key ID to analyze.

    Returns:
        dict: Dictionary with extracted 'user_id' and 'email', or None if extraction fails.
    """
    log_info(f"[Key Analysis] Extracting user info for key {key_id}")

    try:
        # Запуск команды для получения информации о ключе
        result = subprocess.run(
            ["gpg", "--list-keys", "--with-colons", key_id],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            log_warning(f"[Key Analysis] Failed to find key {key_id}")
            return None

        user_info = {"user_id": None, "email": None}
        for line in result.stdout.splitlines():
            # Проверка строки UID
            if line.startswith("uid:"):
                parts = line.split(":")
                if len(parts) > 9:  # UID находится в 10-м поле
                    user_id = parts[9]
                    email = extract_email_from_uid(user_id)
                    if user_id:
                        user_info["user_id"] = user_id.strip()
                    if email:
                        user_info["email"] = email.strip()
                    log_info(f"[Key Analysis] Extracted UID: {user_id}, Email: {email}")
                    break

        # Логируем результат
        if user_info["user_id"] or user_info["email"]:
            log_info(f"[Key Analysis] Extracted user info for key {key_id}: {user_info}")
        else:
            log_warning(f"[Key Analysis] No user ID or email found for key {key_id}")

        return user_info
    except subprocess.SubprocessError as e:
        log_error(f"[Key Analysis] Failed to extract user info for key {key_id}: {e}")
        return None


def extract_email_from_uid(uid):
    """
    Extracts an email address from a GPG UID string.

    Args:
        uid (str): User ID string to extract email from.

    Returns:
        str or None: Extracted email, or None if not found.
    """
    import re

    # Используем регулярное выражение для извлечения email
    email_pattern = r"<([^>]+)>"
    match = re.search(email_pattern, uid)
    if match:
        return match.group(1)
    return None


def are_keys_related(key_user_info_map):
    """
    Checks if multiple keys used in signatures are related (e.g., by email or user ID).
    Verifies if one key is signed by another in the map.
    """
    key_ids = list(key_user_info_map.keys())

    for i, key_id in enumerate(key_ids):
        for other_key_id in key_ids[i + 1:]:
            if is_key_verified(key_id, other_key_id) or is_key_verified(other_key_id, key_id):
                log_info(f"[Key Analysis] Keys {key_id} and {other_key_id} are related.")
                return True

    log_warning("[Key Analysis] No direct relationships found between keys.")
    return False


def is_legitimate_key_change(key_user_info_map):
    """
    Checks if the key change is legitimate (e.g., signed by the same user).
    """
    user_ids = set()
    emails = set()

    for key_id, user_info in key_user_info_map.items():
        if user_info["user_id"]:
            user_ids.add(user_info["user_id"])
        if user_info["email"]:
            emails.add(user_info["email"])

    if len(user_ids) == 1 and len(emails) == 1:
        log_info("[Key Analysis] Key change appears legitimate based on consistent user ID and email.")
        return True

    log_warning("[Key Analysis] Key change does not appear legitimate.")
    return False
