import requests
from xml.etree import ElementTree as ET
from utils.logging import log_warning, log_info, log_error
from repositories.jboss import check_jboss
from repositories.jitpack import check_jitpack, fetch_github_tags
from repositories.sonatype import check_sonatype
from repositories.sonatype_central import check_repository

REPOSITORIES = [
    {"name": "Sonatype", "check_function": check_sonatype, "base_url": "https://s01.oss.sonatype.org/content/repositories/releases"},
    {"name": "Sonatype Central", "check_function": check_repository, "base_url": "https://repo1.maven.org/maven2"},
    {"name": "JitPack", "check_function": check_jitpack, "base_url": None},
    {"name": "JBoss", "check_function": check_jboss, "base_url": "https://repository.jboss.org/nexus/content/repositories/public"},
]


def get_available_extensions(base_repository_url, group_id, artifact_id, version):
    """
    Checks which extensions are available for a given artifact and version.
    """
    available_extensions = []
    possible_extensions = ["jar", "aar", "pom", "module"]

    for extension in possible_extensions:
        file_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.{extension}"
        try:
            response = requests.head(file_url, timeout=5)
            if response.status_code == 200:
                available_extensions.append(extension)
                log_info(f"[Extension Check] Found extension '{extension}' for {artifact_id}:{version} at {file_url}")
            elif response.status_code == 404:
                log_info(f"[Extension Check] Extension '{extension}' not found for {artifact_id}:{version}")
            else:
                log_warning(f"[Extension Check] Unexpected status code {response.status_code} for {file_url}")
        except requests.RequestException as e:
            log_error(f"[Extension Check] Request failed for {file_url}: {e}")

    if not available_extensions:
        log_warning(f"[Extension Check] No valid extensions found for {artifact_id}:{version} in {base_repository_url}")

    return available_extensions


def find_in_repositories(group_id, artifact_id, version, jitpack_token=""):
    results = []
    for repo in REPOSITORIES:
        try:
            if repo["name"] == "JitPack":
                result = check_jitpack(group_id, artifact_id, version, token=jitpack_token)
            else:
                result = repo["check_function"](group_id, artifact_id, version)

            if result and isinstance(result, tuple) and result[0]:  # Проверка валидности результата
                artifact_url, base_repository_url = result
                log_info(f"[Repository Check] Artifact found in {repo['name']} repository.")
                results.append({
                    "repository": repo["name"],
                    "artifact_url": artifact_url,
                    "base_repository_url": base_repository_url
                })
            else:
                log_info(f"[Repository Check] Artifact not found in {repo['name']} repository.")
        except Exception as e:
            log_warning(f"[Repository Error] {repo['name']} repository: {e}")

    if not results:
        log_warning(f"[Repository Check] No repositories found for {group_id}:{artifact_id}:{version}")

    return results  # Возвращает список результатов вместо одного объекта


def fetch_versions_from_metadata(base_repository_url, group_id, artifact_id):
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        response = requests.get(metadata_url, timeout=10)
        response.raise_for_status()
        metadata_xml = ET.fromstring(response.content)
        versions = [version.text for version in metadata_xml.findall(".//version")]
        log_info(f"[Version Retrieval] Found versions in {base_repository_url} for {group_id}:{artifact_id}: {versions}")
        return versions
    except requests.RequestException as e:
        log_warning(f"[Version Retrieval] HTTP error while accessing {metadata_url}: {e}")
    except ET.ParseError as e:
        log_warning(f"[Version Retrieval] XML parsing error for {metadata_url}: {e}")
    except Exception as e:
        log_error(f"[Version Retrieval] Unexpected error for {metadata_url}: {e}")
    return []


def compare_versions_across_repositories(group_id, artifact_id, version=None):
    """
    Сравнивает версии между репозиториями и выявляет несоответствия.
    Учитывает только репозитории, в которых есть хотя бы одна версия.
    """
    version_map = {}

    # Собираем версии из всех репозиториев
    for repo in REPOSITORIES:
        try:
            if repo["name"] == "JitPack":
                owner = group_id.split('.')[-1]
                versions = fetch_github_tags(owner, artifact_id)
            else:
                versions = fetch_versions_from_metadata(repo["base_url"], group_id, artifact_id)

            if versions:
                normalized_versions = {normalize_version(ver) for ver in versions}
                version_map[repo["name"]] = normalized_versions
                log_info(f"[Version Check] Repository {repo['name']} returned versions: {sorted(normalized_versions)}")
            else:
                log_info(f"[Version Check] No versions found in {repo['name']} for {group_id}:{artifact_id}")
        except Exception as e:
            log_warning(f"[Version Check] Error checking versions in {repo['name']} repository: {e}")
            version_map[repo["name"]] = set()

    # Удаляем репозитории, где не найдено ни одной версии
    filtered_version_map = {repo: versions for repo, versions in version_map.items() if versions}

    # Логируем исключенные репозитории
    excluded_repos = [repo for repo in version_map if repo not in filtered_version_map]
    if excluded_repos:
        log_info(f"[Version Comparison] Excluding repositories with no versions: {excluded_repos}")

    if not filtered_version_map:
        log_info("[Version Comparison] No versions found in any relevant repository.")
        return {"version_comparison": {}, "differing_versions": [], "is_consistent": True}

    # Логируем оставшиеся репозитории для сравнения
    log_info(f"[Version Comparison] Relevant repositories for comparison: {list(filtered_version_map.keys())}")

    # Объединение всех уникальных версий для сравнения
    all_versions = set().union(*filtered_version_map.values())

    # Логируем объединенные версии
    log_info(f"[Version Comparison] All unique versions to compare: {sorted(all_versions)}")

    # Сравнение наличия каждой версии в репозиториях
    version_comparison = {
        version: {repo: (version in versions) for repo, versions in filtered_version_map.items()}
        for version in all_versions
    }

    # Логируем результат сравнения версий
    log_info(f"[Version Comparison] Version presence across repositories: {version_comparison}")

    # Проверка согласованности версий
    differing_versions = [
        version
        for version, repos in version_comparison.items()
        if any(repos.values()) and not all(repos.values())
    ]
    is_consistent = len(differing_versions) == 0

    if is_consistent:
        log_info("[Version Comparison] Versions consistent across relevant repositories.")
    else:
        log_warning(f"[Version Comparison] Differing versions across repositories: {sorted(differing_versions)}")

    return {
        "version_comparison": version_comparison,
        "differing_versions": sorted(differing_versions),
        "is_consistent": is_consistent,
    }


def format_repository_results(group_id, artifact_id, version):
    """
    Формирует отчет о наличии артефакта и различиях версий в репозиториях.

    Args:
        group_id (str): Группа артефакта.
        artifact_id (str): Идентификатор артефакта.
        version (str): Версия артефакта.

    Returns:
        dict: Форматированные результаты.
    """
    repositories_results = find_in_repositories(group_id, artifact_id, version)
    version_comparison_result = compare_versions_across_repositories(group_id, artifact_id)

    formatted_results = {
        "artifact": f"{group_id}:{artifact_id}:{version}",
        "repository_results": repositories_results,
        "version_comparison": version_comparison_result["version_comparison"],
        "repositories_found": len(repositories_results),
        "differing_versions": version_comparison_result["differing_versions"],
        "status": "consistent" if version_comparison_result["is_consistent"] else "inconsistent",
    }

    if not repositories_results:
        log_warning(f"[Repository Results] No repositories found for {group_id}:{artifact_id}:{version}")

    # Логирование итогового статуса
    if version_comparison_result["is_consistent"]:
        log_info(f"[Status] Versions are consistent across repositories for {group_id}:{artifact_id}.")
    else:
        log_warning(f"[Status] Versions differ across repositories for {group_id}:{artifact_id}: {version_comparison_result['differing_versions']}")

    return formatted_results



def normalize_version(version):
    """
    Normalizes a version string by removing any common prefixes like 'v'.
    Args:
        version (str): The version string to normalize.
    Returns:
        str: The normalized version string.
    """
    return version.lstrip("v").strip()
