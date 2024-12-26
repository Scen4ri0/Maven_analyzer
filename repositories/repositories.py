import aiohttp
import asyncio
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


async def get_available_extensions(base_repository_url, group_id, artifact_id, version):
    """
    Checks which extensions are available for a given artifact and version asynchronously.
    """
    available_extensions = []
    possible_extensions = ["jar", "aar", "pom", "module"]

    async with aiohttp.ClientSession() as session:
        tasks = []
        for extension in possible_extensions:
            file_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}.{extension}"
            tasks.append(check_extension(session, file_url, extension))

        results = await asyncio.gather(*tasks)

    available_extensions = [ext for ext in results if ext]
    if not available_extensions:
        log_warning(f"[Extension Check] No valid extensions found for {artifact_id}:{version} in {base_repository_url}")

    return available_extensions


async def check_extension(session, url, extension):
    """
    Helper function to check the availability of a specific extension asynchronously.
    """
    try:
        async with session.head(url, timeout=10) as response:
            if response.status == 200:
                log_info(f"[Extension Check] Found extension '{extension}' at {url}")
                return extension
            elif response.status == 404:
                log_info(f"[Extension Check] Extension '{extension}' not found at {url}")
            else:
                log_warning(f"[Extension Check] Unexpected status code {response.status} for {url}")
    except aiohttp.ClientError as e:
        log_error(f"[Extension Check] Error checking {url}: {e}")
    return None


async def find_in_repositories(group_id, artifact_id, version, jitpack_token=""):
    results = []

    async def process_repository(repo):
        try:
            if repo["name"] == "JitPack":
                result = await check_jitpack(group_id, artifact_id, version, token=jitpack_token)
            else:
                result = await repo["check_function"](group_id, artifact_id, version)

            if result and isinstance(result, tuple) and result[0]:  # Проверка валидности результата
                artifact_url, base_repository_url = result
                log_info(f"[Repository Check] Artifact found in {repo['name']} repository.")
                return {
                    "repository": repo["name"],
                    "artifact_url": artifact_url,
                    "base_repository_url": base_repository_url
                }
            else:
                log_info(f"[Repository Check] Artifact not found in {repo['name']} repository.")
        except Exception as e:
            log_warning(f"[Repository Error] {repo['name']} repository: {e}")
        return None

    tasks = [process_repository(repo) for repo in REPOSITORIES]
    results = await asyncio.gather(*tasks)

    results = [res for res in results if res is not None]
    if not results:
        log_warning(f"[Repository Check] No repositories found for {group_id}:{artifact_id}:{version}")

    return results


async def fetch_versions_from_metadata(base_repository_url, group_id, artifact_id):
    metadata_url = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(metadata_url, timeout=10) as response:
                response.raise_for_status()
                metadata_xml = ET.fromstring(await response.text())
                versions = [version.text for version in metadata_xml.findall(".//version")]
                log_info(f"[Version Retrieval] Found versions in {base_repository_url} for {group_id}:{artifact_id}: {versions}")
                return versions
    except aiohttp.ClientError as e:
        log_warning(f"[Version Retrieval] HTTP error while accessing {metadata_url}: {e}")
    except ET.ParseError as e:
        log_warning(f"[Version Retrieval] XML parsing error for {metadata_url}: {e}")
    except Exception as e:
        log_error(f"[Version Retrieval] Unexpected error for {metadata_url}: {e}")
    return []


async def compare_versions_across_repositories(group_id, artifact_id, version=None):
    """
    Сравнивает версии между репозиториями и выявляет несоответствия.
    Учитывает только репозитории, в которых есть хотя бы одна версия.
    """
    version_map = {}

    async def fetch_versions(repo):
        try:
            if repo["name"] == "JitPack":
                owner = group_id.split('.')[-1]
                return repo["name"], await fetch_github_tags(owner, artifact_id)
            else:
                return repo["name"], await fetch_versions_from_metadata(repo["base_url"], group_id, artifact_id)
        except Exception as e:
            log_warning(f"[Version Check] Error checking versions in {repo['name']} repository: {e}")
            return repo["name"], set()

    tasks = [fetch_versions(repo) for repo in REPOSITORIES]
    results = await asyncio.gather(*tasks)

    for repo_name, versions in results:
        if versions:
            normalized_versions = {normalize_version(ver) for ver in versions}
            version_map[repo_name] = normalized_versions
            log_info(f"[Version Check] Repository {repo_name} returned versions: {sorted(normalized_versions)}")

    # Удаляем репозитории, где не найдено ни одной версии
    filtered_version_map = {repo: versions for repo, versions in version_map.items() if versions}

    if not filtered_version_map:
        log_info("[Version Comparison] No versions found in any relevant repository.")
        return {"version_comparison": {}, "differing_versions": [], "is_consistent": True}

    # Объединение всех уникальных версий для сравнения
    all_versions = set().union(*filtered_version_map.values())

    # Сравнение наличия каждой версии в репозиториях
    version_comparison = {
        version: {repo: (version in versions) for repo, versions in filtered_version_map.items()}
        for version in all_versions
    }

    # Проверка согласованности версий
    differing_versions = [
        version
        for version, repos in version_comparison.items()
        if any(repos.values()) and not all(repos.values())
    ]
    is_consistent = len(differing_versions) == 0

    return {
        "version_comparison": version_comparison,
        "differing_versions": sorted(differing_versions),
        "is_consistent": is_consistent,
    }


def normalize_version(version):
    """
    Normalizes a version string by removing any common prefixes like 'v'.
    Args:
        version (str): The version string to normalize.
    Returns:
        str: The normalized version string.
    """
    return version.lstrip("v").strip()
