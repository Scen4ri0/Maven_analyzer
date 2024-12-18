import subprocess
from utils.logging import log_info, log_warning, log_error

KEY_SERVERS = [
    "hkps://keyserver.ubuntu.com",
    "hkps://keys.openpgp.org",
    "hkps://pgp.mit.edu"
]

def verify_signature(file_path, signature_path):
    """
    A simple wrapper for verifying file signatures.
    """
    return verify_signature_with_key_handling(file_path, signature_path)

def verify_signature_with_key_handling(file_path, signature_path):
    """
    Verifies the signature of a file and attempts to fetch missing keys if needed.
    Ignores expired keys if the signature is otherwise valid.
    """
    try:
        log_info(f"[Signature Verification] Verifying {file_path} with {signature_path}")
        result = subprocess.run(
            ['gpg', '--status-fd', '1', '--verify', signature_path, file_path],
            capture_output=True,
            text=True,
            timeout=10
        )

        stdout = result.stdout
        if "[GNUPG:] VALIDSIG" in stdout:
            key_id = get_signature_key_id(signature_path)
            if "[GNUPG:] KEYEXPIRED" in stdout:
                log_warning(f"[Signature Verification] Signature valid for {file_path} but key {key_id} has expired.")
            else:
                log_info(f"[Signature Verification] Signature valid for {file_path}. Key ID: {key_id}")
            return True, key_id

        if "[GNUPG:] NO_PUBKEY" in stdout:
            for line in stdout.splitlines():
                if "[GNUPG:] NO_PUBKEY" in line:
                    missing_key = line.split()[-1]
                    log_warning(f"[Signature Verification] Missing public key {missing_key}. Attempting to fetch.")

                    # Проверяем, есть ли ключ в локальной GPG-базе
                    if is_key_loaded(missing_key):
                        log_info(f"[GPG Key] Key {missing_key} already present in GPG keyring. Skipping fetch.")
                        continue

                    # Пытаемся загрузить ключ
                    if fetch_missing_gpg_key(missing_key):
                        log_info(f"[GPG Key] Key {missing_key} fetched successfully. Retrying verification.")
                        return verify_signature_with_key_handling(file_path, signature_path)
            
            log_warning(f"[Signature Verification] Public key not fetched. Signature invalid for {file_path}.")
        else:
            log_warning(f"[Signature Verification] Invalid signature for {file_path}")
            log_warning(f"[Signature Verification Output] {stdout}")

        return False, None
    except subprocess.TimeoutExpired:
        log_warning(f"[Signature Verification] Timeout while verifying {file_path}")
        return False, None
    except Exception as e:
        log_error(f"[Signature Verification] Error verifying signature for {file_path}: {e}")
        return False, None


def is_key_loaded(key_id):
    """
    Checks if a GPG key is already loaded in the local keyring.
    """
    try:
        result = subprocess.run(
            ['gpg', '--list-keys', key_id],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            log_info(f"[GPG Key Check] Key {key_id} is already loaded in the GPG keyring.")
            return True
        return False
    except Exception as e:
        log_error(f"[GPG Key Check] Error while checking key {key_id}: {e}")
        return False


def get_signature_key_id(signature_path):
    """
    Extracts the key ID from the .asc signature file.
    """
    try:
        result = subprocess.run(
            ['gpg', '--list-packets', signature_path],
            capture_output=True,
            text=True,
            errors='replace',
            timeout=10
        )
        for line in result.stdout.splitlines():
            if "keyid" in line:
                key_id = line.split("keyid ")[-1].strip()
                log_info(f"[Key Extract] Key ID {key_id} extracted from {signature_path}.")
                return key_id
    except Exception as e:
        log_error(f"[Key Extract] Failed to extract key ID from {signature_path}: {e}")
    return None


def fetch_missing_gpg_key(key_id):
    """
    Fetches a missing GPG key from multiple public key servers.
    """
    for server in KEY_SERVERS:
        try:
            log_info(f"[GPG Key] Trying to fetch key {key_id} from {server}...")
            result = subprocess.run(
                ['gpg', '--keyserver', server, '--recv-keys', key_id],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                # Проверяем, содержит ли ключ User ID
                if not is_valid_key(key_id):
                    log_warning(f"[GPG Key] Key {key_id} fetched but contains no User ID. Skipping.")
                    continue
                log_info(f"[GPG Key] Successfully imported key {key_id} from {server}.")
                return True
            else:
                log_warning(f"[GPG Key] Failed to fetch key {key_id} from {server}. Output: {result.stderr.strip()}")
        except Exception as e:
            log_error(f"[GPG Key] Error while fetching key {key_id} from {server}: {e}")
    log_error(f"[GPG Key] Unable to fetch key {key_id} from all servers.")
    return False

def is_valid_key(key_id):
    """
    Checks if a GPG key is valid (contains User ID).
    """
    try:
        result = subprocess.run(
            ['gpg', '--list-keys', '--with-colons', key_id],
            capture_output=True,
            text=True,
            timeout=5
        )
        # GPG форматирует User ID с помощью строки "uid:"
        if "uid:" in result.stdout:
            log_info(f"[GPG Key] Key {key_id} is valid and contains User ID.")
            return True
        log_warning(f"[GPG Key] Key {key_id} does not contain User ID.")
        return False
    except Exception as e:
        log_error(f"[GPG Key] Error while validating key {key_id}: {e}")
        return False