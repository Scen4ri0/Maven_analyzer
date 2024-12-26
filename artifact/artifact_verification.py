from datetime import datetime
from artifact.artifact_status import ArtifactStatus
from artifact.signature_verification import verify_signature_with_key_handling
from artifact.key_analysis import (
    are_keys_related,
    is_legitimate_key_change,
    extract_key_user_info,
)
from artifact.version_management import compare_versions,parse_version, get_latest_versions
from utils.logging import log_info, log_warning, log_error
from utils.file_operations import download_file, save_file, clean_up_files
from domain.domain_utils import group_id_to_domain, is_domain_available, is_recently_updated
from repositories.repositories import find_in_repositories, get_available_extensions, compare_versions_across_repositories
from repositories.jitpack import fetch_github_contributors
from xml.etree import ElementTree as ET
import requests
from datetime import datetime, timezone
import asyncio
import aiohttp
import whois

async def process_artifact(artifact, check_domain=False, github_token=None):
    """
    Processes an artifact to verify its status across repositories, domain availability,
    version consistency, and signature verification. Also checks for contributor differences.

    Args:
        artifact (str): The artifact in the format group_id:artifact_id:version.
        check_domain (bool): Flag to enable domain and publication date checks.
        github_token (str, optional): GitHub token for authenticated requests.

    Returns:
        dict: A dictionary containing verification results for the artifact.
    """
    try:
        group_id, artifact_id, version = artifact.split(':')
    except ValueError:
        log_error(f"[Artifact Parsing] Invalid artifact format: {artifact}")
        return {"artifact": artifact, "error": "Invalid format"}

    log_info(f"[Processing] Start verification for artifact: {artifact}")
    
    result = {"artifact": artifact}
    tasks = []

    # Проверка домена и обновлений
    if check_domain:
        tasks.append(check_domain_status(group_id))
        tasks.append(extract_publication_date(
            base_repository_url="https://repo1.maven.org/maven2",  # Укажите базовый URL
            group_id=group_id,
            artifact_id=artifact_id,
            version=version
        ))

    # Проверка репозиториев
    tasks.append(find_in_repositories(group_id, artifact_id, version))

    # Проверка подписей и контрибьюторов
    tasks.append(check_signatures_and_contributors(group_id, artifact_id, version, github_token))

    # Выполняем все задачи параллельно
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Обработка результата проверки домена
    if check_domain:
        domain_result = results[0]
        if isinstance(domain_result, tuple):
            domain_status, recently_updated = domain_result
            result.update({
                "domain": domain_status,
                "recently_updated": recently_updated,
            })
        else:
            log_warning(f"[Domain Check] Error occurred: {domain_result}")
            result.update({"domain": "error", "recently_updated": False})

        # Обработка результата публикации
        publication_date_result = results[1]
        recent_threshold = datetime(2024, 1, 1, tzinfo=timezone.utc)
        if isinstance(publication_date_result, datetime):
            published_recently = publication_date_result >= recent_threshold
            log_info(f"[Publication Date] Artifact published recently: {published_recently}")
            result["published_recently"] = published_recently
        else:
            log_warning(f"[Publication Date] Could not determine publication date: {publication_date_result}")
            result["published_recently"] = False

    # Обработка результата проверки репозиториев
    repository_result = results[2 if check_domain else 0]
    if isinstance(repository_result, list) and repository_result:
        log_info(f"[Repository Check] Found in {len(repository_result)} repositories.")
        result["repositories_found"] = len(repository_result)
    else:
        log_warning(f"[Repository Check] Artifact '{artifact}' not found in any repository.")
        result.update({
            "repositories_found": 0,
            "version_differences": False,
            "signature": ArtifactStatus.NOT_FOUND.value,
            "contributors_diff": False,
            "risk": "low"
        })
        return result

    # Обработка результата проверки подписей и контрибьюторов
    signature_and_contributors_result = results[3 if check_domain else 1]
    if isinstance(signature_and_contributors_result, tuple):
        signature_status, contributors_diff, version_differences, risk = signature_and_contributors_result
        result.update({
            "signature": signature_status.value,
            "contributors_diff": contributors_diff,
            "version_differences": version_differences,
            "risk": risk,
        })
    else:
        log_warning(f"[Signature/Contributor Check] Error occurred: {signature_and_contributors_result}")
        result.update({
            "version_differences": False,
            "signature": ArtifactStatus.NOT_SIGNED.value,
            "contributors_diff": False,
            "risk": "unknown",
        })

    log_info(f"[Processing] Verification complete for artifact: {artifact}")
    return result




async def check_domain_status(group_id):
    """
    Checks the domain availability and recent updates.
    """
    domain = group_id_to_domain(group_id)
    log_info(f"[Domain Check] Checking domain: {domain}")
    
    try:
        domain_status = "vulnerable" if is_domain_available(domain) else "ok"
        recent_update = is_recently_updated(domain)
        
        if recent_update.get("error"):
            log_warning(f"[Domain Check] Error checking updates: {recent_update['error']}")
            recent_update_status = False
        else:
            recent_update_status = recent_update.get("recently_updated", False)

        return domain_status, recent_update_status

    except Exception as e:
        log_error(f"[Domain Check] Unexpected error for domain '{domain}': {e}")
        return "error", False

### Асинхронная проверка подписей и контрибьюторов
async def check_signatures_and_contributors(group_id, artifact_id, version, github_token):
    """
    Checks signatures, contributors, and calculates risk.
    """
    base_repository_url = f"https://repo1.maven.org/maven2"
    signature_status = await compare_signatures_across_versions(group_id, artifact_id, version, base_repository_url)
    version_comparison = await compare_versions_across_repositories(group_id, artifact_id, version)
    version_differences = len(version_comparison["differing_versions"]) > 0

    contributors_diff = False
    versions_to_check = await get_selected_versions(base_repository_url, group_id, artifact_id, version)
    if versions_to_check:
        differences = await compare_contributors_across_versions(group_id.split(".")[-1], artifact_id, versions_to_check, github_token)
        contributors_diff = bool(differences)

    risk = calculate_risk(version_differences, contributors_diff, signature_status)
    return signature_status, contributors_diff, version_differences, risk




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


async def extract_publication_date(base_repository_url, group_id, artifact_id, version):
    """
    Асинхронно извлекает дату публикации для конкретной версии из POM-файла или HTTP-заголовков.

    Args:
        base_repository_url (str): Базовый URL репозитория.
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        version (str): Версия артефакта.

    Returns:
        datetime: Дата публикации (если удалось определить), иначе None.
    """
    pom_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

    async with aiohttp.ClientSession() as session:
        try:
            # Попытка скачать POM-файл
            async with session.get(pom_url, timeout=10) as response:
                if response.status == 200:
                    pom_content = await response.text()
                    root = ET.fromstring(pom_content)
                    
                    # Попытка найти inceptionYear
                    inception_year = root.find(".//inceptionYear")
                    if inception_year is not None:
                        return datetime.strptime(inception_year.text.strip(), "%Y").replace(tzinfo=timezone.utc)

                    # Попытка найти releaseDate
                    release_date = root.find(".//releaseDate")
                    if release_date is not None:
                        return datetime.strptime(release_date.text.strip(), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                else:
                    log_warning(f"[Publication Date] Не удалось загрузить POM-файл: {pom_url} (Статус: {response.status})")
        except Exception as e:
            log_warning(f"[Publication Date] Ошибка при обработке POM-файла: {e}")

        # Если POM недоступен, используем HTTP-заголовок Last-Modified
        try:
            async with session.head(pom_url, timeout=10) as head_response:
                if head_response.status == 200:
                    last_modified = head_response.headers.get("Last-Modified")
                    if last_modified:
                        return datetime.strptime(last_modified, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
                else:
                    log_warning(f"[Publication Date] Не удалось получить заголовок Last-Modified: {pom_url}")
        except Exception as e:
            log_warning(f"[Publication Date] Ошибка при получении Last-Modified: {e}")

    return None  # Если все попытки не удались


import aiohttp

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



import aiohttp

async def compare_contributors_across_versions(owner, repo, versions, token=None):
    """
    Асинхронно сравнивает контрибьюторов между текущей версией и предыдущими.

    Args:
        owner (str): Владелец репозитория.
        repo (str): Название репозитория.
        versions (list): Список версий для анализа.
        token (str, optional): GitHub токен.

    Returns:
        dict: Информация о различиях контрибьюторов между версиями.
    """
    contributors_map = {}
    differences = {}

    async def fetch_contributors(session, version):
        """
        Асинхронно получает список контрибьюторов для заданной версии.
        """
        try:
            contributors = await fetch_github_contributors(owner, repo, version, token, session)
            contributors_map[version] = set(contributors)
            log_info(f"[GitHub Contributors] Contributors for {repo}@{version}: {contributors}")
        except Exception as e:
            log_error(f"[GitHub Contributors] Error fetching contributors for {repo}@{version}: {e}")
            contributors_map[version] = set()

    # Создаем асинхронные задачи для получения контрибьюторов
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_contributors(session, version) for version in versions]
        await asyncio.gather(*tasks)

    # Сравниваем контрибьюторов между базовой (последней) версией и предыдущими
    base_version = versions[-1]
    base_contributors = contributors_map.get(base_version, set())

    for version in versions[:-1]:
        current_contributors = contributors_map.get(version, set())
        added = base_contributors - current_contributors
        removed = current_contributors - base_contributors

        # Логируем добавленных и удалённых контрибьюторов для каждой версии
        if added or removed:
            log_info(f"[GitHub Contributors] Differences for {repo}: {version} -> {base_version}")
            log_info(f"  Added contributors: {list(added)}")
            log_info(f"  Removed contributors: {list(removed)}")

            differences[version] = {"added": list(added), "removed": list(removed)}

    return differences



async def get_selected_versions(base_repository_url, group_id, artifact_id, start_version):
    """
    Асинхронно извлекает текущую и до 4 предыдущих версий артефакта из maven-metadata.xml.

    Args:
        base_repository_url (str): Базовый URL репозитория.
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        start_version (str): Текущая версия для анализа.

    Returns:
        list: Список версий для анализа (включая текущую и до 4 предыдущих).
    """
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url, timeout=10) as response:
                if response.status != 200:
                    log_warning(f"[Version Retrieval] Failed to fetch metadata from {metadata_url}. HTTP Status: {response.status}")
                    return []

                metadata_content = await response.text()
                try:
                    metadata_xml = ET.fromstring(metadata_content)
                    all_versions = [version.text for version in metadata_xml.findall(".//version")]
                    log_info(f"[Version Retrieval] Found versions: {all_versions}")
                except ET.ParseError as e:
                    log_error(f"[Version Retrieval] Failed to parse XML from {metadata_url}: {e}")
                    return []

        # Проверяем наличие текущей версии
        if start_version not in all_versions:
            log_warning(f"[Version Check] Start version {start_version} not found.")
            return []

        # Выбираем текущую и до 4 предыдущих версий
        start_index = all_versions.index(start_version)
        selected_versions = all_versions[max(0, start_index - 4): start_index + 1]
        log_info(f"[Version Retrieval] Selected versions for analysis: {selected_versions}")
        return selected_versions

    except aiohttp.ClientError as e:
        log_error(f"[Version Retrieval] Client error while accessing {metadata_url}: {e}")
    except asyncio.TimeoutError:
        log_error(f"[Version Retrieval] Timeout while accessing {metadata_url}")
    except Exception as e:
        log_error(f"[Version Retrieval] Unexpected error: {e}")

    return []  # Возвращаем пустой список при ошибке