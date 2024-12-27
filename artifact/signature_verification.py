import subprocess
import asyncio
import aiohttp
from xml.etree import ElementTree as ET
from utils.logging import log_info, log_warning, log_error
from artifact.artifact_status import ArtifactStatus
from utils.file_operations import save_file, clean_up_files
from artifact.key_analysis import (
    are_keys_related,
    is_legitimate_key_change,
    extract_key_user_info,
)


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


async def compare_signatures_across_versions(group_id, artifact_id, start_version, base_repository_url):
    """
    Асинхронно проверяет подписи для текущей версии и до 4 предыдущих версий артефакта.
    Артефакт считается неподписанным, только если подпись отсутствует во всех версиях.

    Args:
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        start_version (str): Текущая версия для анализа.
        base_repository_url (str): URL базового репозитория.

    Returns:
        ArtifactStatus: Итоговый статус подписи.
    """
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url, timeout=10) as response:
                if response.status != 200:
                    log_error(f"[Version Retrieval] Failed to fetch metadata: {metadata_url} (Status: {response.status})")
                    return ArtifactStatus.NOT_SIGNED

                metadata_xml = ET.fromstring(await response.text())
                all_versions = [version.text for version in metadata_xml.findall(".//version")]
                log_info(f"[Version Retrieval] Found versions: {all_versions}")
    except Exception as e:
        log_error(f"[Version Retrieval] Failed to fetch or parse metadata: {e}")
        return ArtifactStatus.NOT_SIGNED

    # Проверяем наличие текущей версии
    if start_version not in all_versions:
        log_error(f"[Version Check] Start version {start_version} not found in retrieved versions: {all_versions}")
        return ArtifactStatus.NOT_SIGNED

    # Отбираем текущую и до 4 предыдущих версий
    start_index = all_versions.index(start_version)
    selected_versions = all_versions[max(0, start_index - 4): start_index + 1]
    log_info(f"[Signature Check] Selected versions for verification: {selected_versions}")

    # Инициализация переменных
    signatures_found = 0
    valid_signatures = 0
    developer_key_ids = set()
    key_user_info_map = {}
    invalid_versions = []

    async def fetch_file(session, url):
        """
        Асинхронно загружает файл по URL.
        """
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    return await response.read()
                elif response.status == 404:
                    log_warning(f"[Fetch File] File not found: {url}")
                else:
                    log_warning(f"[Fetch File] Unexpected status {response.status} for {url}")
        except Exception as e:
            log_error(f"[Fetch File] Error fetching {url}: {e}")
        return None

    # Проверяем подписи
    async with aiohttp.ClientSession() as session:
        for version in selected_versions:
            log_info(f"[Signature Check] Checking version {version}")
            signature_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom.asc"
            file_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

            # Проверяем наличие подписи перед скачиванием
            try:
                async with session.head(signature_url, timeout=5) as head_response:
                    if head_response.status == 404:
                        log_warning(f"[Signature Check] Signature file not found for version {version}.")
                        continue
                    elif head_response.status == 200:
                        signatures_found += 1  # Учитываем, что хотя бы один файл подписи найден
            except Exception as e:
                log_warning(f"[Signature Check] Error while verifying signature availability for version {version}: {e}")
                continue

            # Загрузка файлов и проверка подписи
            try:
                file_content = await fetch_file(session, file_url)
                signature_content = await fetch_file(session, signature_url)

                if not file_content or not signature_content:
                    invalid_versions.append(version)
                    continue

                save_file(f"{artifact_id}-{version}.pom", file_content)
                save_file(f"{artifact_id}-{version}.pom.asc", signature_content)

                signature_valid, key_id = verify_signature_with_key_handling(
                    f"{artifact_id}-{version}.pom",
                    f"{artifact_id}-{version}.pom.asc"
                )

                if signature_valid:
                    valid_signatures += 1
                    log_info(f"[Signature Check] Valid signature for version {version}.")
                    if key_id:
                        developer_key_ids.add(key_id)
                        if key_id not in key_user_info_map:
                            key_user_info_map[key_id] = extract_key_user_info(key_id)
                else:
                    log_warning(f"[Signature Check] Invalid signature for version {version}.")
                    invalid_versions.append(version)
            except Exception as e:
                log_error(f"[Signature Check] Error verifying signature for version {version}: {e}")
            finally:
                clean_up_files(f"{artifact_id}-{version}", extensions=["pom", "pom.asc"])

    # Оценка итогового статуса
    if signatures_found == 0:  # Нет подписей ни для одной версии
        return ArtifactStatus.NOT_SIGNED

    if len(developer_key_ids) > 1:
        if are_keys_related(key_user_info_map):
            return ArtifactStatus.KEY_CHANGED_OK
        elif is_legitimate_key_change(key_user_info_map):
            return ArtifactStatus.LEGITIMATE_KEY_CHANGE
        else:
            return ArtifactStatus.POTENTIALLY_EXPLOITED

    if invalid_versions and valid_signatures > 0:
        return ArtifactStatus.KEY_CHANGED_OK

    if valid_signatures == 0:
        return ArtifactStatus.POTENTIALLY_EXPLOITED

    return ArtifactStatus.OK