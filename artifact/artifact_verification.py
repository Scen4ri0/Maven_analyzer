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
from repositories.repositories import find_in_repositories, get_available_extensions, format_repository_results, compare_versions_across_repositories
from repositories.jitpack import fetch_github_contributors
from xml.etree import ElementTree
import requests
from datetime import datetime, timezone

def process_artifact(artifact, check_domain=False, github_token=None):
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
    
    # Инициализация результатов
    result = {"artifact": artifact}

    # Проверка домена и обновлений, если включена
    if check_domain:
        domain = group_id_to_domain(group_id)
        log_info(f"[Domain Check] Checking domain: {domain}")
        domain_status = "vulnerable" if is_domain_available(domain) else "ok"
        recent_update = is_recently_updated(domain)
        recently_updated = recent_update.get("recently_updated", False)

        log_info(f"[Domain Check] Domain '{domain}' status: {domain_status}, Recently updated: {recently_updated}")
        result["domain"] = domain_status
        result["recently_updated"] = recently_updated

    # Проверка наличия артефакта в репозиториях
    repository_results = find_in_repositories(group_id, artifact_id, version)
    if not repository_results:
        log_warning(f"[Repository Check] Artifact '{artifact}' not found in any repository.")
        result.update({
            "repositories_found": 0,
            "version_differences": False,
            "signature": ArtifactStatus.NOT_FOUND.value,
            "contributors_diff": False,
            "risk": "low"
        })
        return result

    log_info(f"[Repository Check] Found in {len(repository_results)} repositories.")

    # Проверка различий в версиях
    version_comparison = compare_versions_across_repositories(group_id, artifact_id, version)
    version_differences = len(version_comparison["differing_versions"]) > 0
    log_info(f"[Version Comparison] Version differences: {version_differences}")

    # Проверка подписей
    base_repository_url = repository_results[0].get("base_repository_url", "unknown")
    signature_status = compare_signatures_across_versions(group_id, artifact_id, version, base_repository_url)
    log_info(f"[Signature Check] Signature status: {signature_status.value}")

    # Проверка контрибьюторов
    owner = group_id.split('.')[-1]  # Извлекаем owner из group_id
    contributors_diff = False
    try:
        versions_to_check = get_selected_versions(base_repository_url, group_id, artifact_id, version)
        if owner and artifact_id and versions_to_check:
            log_info(f"[Contributor Check] Comparing contributors for versions: {versions_to_check}")
            differences = compare_contributors_across_versions(owner, artifact_id, versions_to_check, github_token)
            contributors_diff = bool(differences)

            if contributors_diff:
                log_info(f"[Contributor Check] Contributor differences detected: {differences}")
            else:
                log_info(f"[Contributor Check] No contributor differences detected.")
    except Exception as e:
        log_warning(f"[Contributor Check] Error checking contributors for {artifact}: {e}")

    # Проверка даты публикации, если флаг -d включен
    published_recently = False
    if check_domain:
        publication_date = extract_publication_date(base_repository_url, group_id, artifact_id, version)
        if publication_date:
            published_recently = publication_date >= datetime(2024, 1, 1, tzinfo=timezone.utc)
            log_info(f"[Publication Date] Artifact '{artifact}' recently published: {published_recently}")
        else:
            log_warning(f"[Publication Date] Could not determine publication date for '{artifact}'.")

        result["published_recently"] = published_recently

    # Оценка риска
    risk = calculate_risk(version_differences, contributors_diff, signature_status)
    log_info(f"[Risk Assessment] Risk level for '{artifact}': {risk}")

    # Формирование итогового результата
    result.update({
        "repositories_found": len(repository_results),
        "version_differences": version_differences,
        "signature": signature_status.value,
        "contributors_diff": contributors_diff,
        "risk": risk
    })

    # Удаляем ключи домена, обновлений и публикации, если флаг -d не передан
    if not check_domain:
        result.pop("domain", None)
        result.pop("recently_updated", None)
        result.pop("published_recently", None)

    log_info(f"[Processing] Verification complete for artifact: {artifact}")
    return result



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


def extract_publication_date(base_repository_url, group_id, artifact_id, version):
    """
    Извлекает дату публикации для конкретной версии из POM-файла или HTTP-заголовков.
    """
    import requests
    from xml.etree import ElementTree as ET

    # URL для POM-файла
    pom_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"

    try:
        # Попытка скачать POM-файл
        response = requests.get(pom_url)
        if response.status_code == 200:
            pom_content = response.text
            root = ET.fromstring(pom_content)
            inception_year = root.find(".//inceptionYear")
            if inception_year is not None:
                # Если есть inceptionYear, преобразуем в дату и делаем offset-aware
                return datetime.strptime(inception_year.text.strip(), "%Y").replace(tzinfo=timezone.utc)

            # Пытаемся найти другую дату в POM
            release_date = root.find(".//releaseDate")
            if release_date is not None:
                return datetime.strptime(release_date.text.strip(), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        else:
            log_warning(f"[Publication Date] Не удалось загрузить POM-файл: {pom_url}")
    except Exception as e:
        log_warning(f"[Publication Date] Ошибка при обработке POM-файла: {e}")

    # Если POM недоступен, используем HTTP-заголовок Last-Modified
    try:
        response = requests.head(pom_url)
        if response.status_code == 200:
            last_modified = response.headers.get("Last-Modified")
            if last_modified:
                return datetime.strptime(last_modified, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
    except Exception as e:
        log_warning(f"[Publication Date] Не удалось получить Last-Modified для {pom_url}: {e}")

    return None  # Если все попытки не удались


def compare_signatures_across_versions(group_id, artifact_id, start_version, base_repository_url):
    """
    Проверяет подписи для текущей версии и до 4 предыдущих версий артефакта.
    Артефакт считается неподписанным, только если подпись отсутствует во всех версиях.
    """
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        metadata_xml = ElementTree.fromstring(response.content)
        all_versions = [version.text for version in metadata_xml.findall(".//version")]
        log_info(f"[Version Retrieval] Found versions: {all_versions}")
    except Exception as e:
        log_error(f"[Version Retrieval] Failed to fetch or parse metadata: {e}")
        return ArtifactStatus.NOT_SIGNED

    # Проверяем наличие текущей версии
    if start_version not in all_versions:
        log_error(f"[Version Check] Start version {start_version} not found in retrieved versions: {all_versions}")
        return ArtifactStatus.NOT_SIGNED

    # Выбираем текущую и до 4 предыдущих версий
    start_index = all_versions.index(start_version)
    selected_versions = all_versions[max(0, start_index - 4): start_index + 1]
    log_info(f"[Signature Check] Selected versions for verification: {selected_versions}")

    # Проверяем подписи
    signatures_found = 0
    valid_signatures = 0
    developer_key_ids = set()
    key_user_info_map = {}
    invalid_versions = []
    total_versions_checked = len(selected_versions)

    for version in selected_versions:
        log_info(f"[Signature Check] Checking version {version}")

        # Проверяем наличие подписи перед скачиванием
        signature_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom.asc"
        try:
            head_response = requests.head(signature_url, timeout=5)
            if head_response.status_code == 404:
                log_warning(f"[Signature Check] Signature file not found for version {version}.")
                continue
            elif head_response.status_code == 200:
                signatures_found += 1  # Учитываем, что хотя бы один файл подписи найден
        except Exception as e:
            log_warning(f"[Signature Check] Error while verifying signature availability for version {version}: {e}")
            continue

        # Скачиваем файлы и проверяем подпись
        try:
            file_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.pom"
            file_content = download_file(file_url)
            signature_content = download_file(signature_url)

            if not file_content or not signature_content:
                log_warning(f"[Signature Check] Missing file or signature for version {version}.")
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


def compare_contributors_across_versions(owner, repo, versions, token=None):
    """
    Сравнивает контрибьюторов между текущей версией и предыдущими.

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

    # Получаем список контрибьюторов для каждой версии
    for version in versions:
        contributors = fetch_github_contributors(owner, repo, version, token)
        contributors_map[version] = set(contributors)
        log_info(f"[GitHub Contributors] Contributors for {repo}@{version}: {contributors}")

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



def get_selected_versions(base_repository_url, group_id, artifact_id, start_version):
    """
    Извлекает текущую и до 4 предыдущих версий артефакта из maven-metadata.xml.

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
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        metadata_xml = ElementTree.fromstring(response.content)
        all_versions = [version.text for version in metadata_xml.findall(".//version")]
        log_info(f"[Version Retrieval] Found versions: {all_versions}")

        # Проверяем наличие текущей версии
        if start_version not in all_versions:
            log_warning(f"[Version Check] Start version {start_version} not found.")
            return []

        # Выбираем текущую и до 4 предыдущих версий
        start_index = all_versions.index(start_version)
        selected_versions = all_versions[max(0, start_index - 4): start_index + 1]
        log_info(f"[Version Retrieval] Selected versions for analysis: {selected_versions}")
        return selected_versions

    except Exception as e:
        log_error(f"[Version Retrieval] Error fetching versions: {e}")
        return []