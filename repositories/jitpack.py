import requests
from utils.logging import log_warning, log_error, log_info

# Define constants for JitPack and GitHub
JITPACK_BASE_URL = "https://jitpack.io"
JITPACK_ARTIFACT_BASE_URL = f"{JITPACK_BASE_URL}/com/github"
GITHUB_TAGS_API_URL = "https://api.github.com/repos"

def fetch_github_tags(owner, repo, token=None):
    """
    Fetches tags (versions) for a given GitHub repository using the GitHub API.
    """
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = f"{GITHUB_TAGS_API_URL}/{owner}/{repo}/tags"
    log_info(f"[GitHub API] Querying tags for {owner}/{repo} at {api_url}")

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        response.raise_for_status()
        tags = [normalize_version(tag["name"]) for tag in response.json()]
        log_info(f"[GitHub API] Found tags for {owner}/{repo}: {tags}")
        return tags
    except requests.RequestException as e:
        log_error(f"[GitHub API] Error fetching tags for {owner}/{repo}: {e}")
    return None

def fetch_github_contributors(owner, repo, version, token=None):
    """
    Fetches a list of contributors for a specific version of a GitHub repository.
    """
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": version}

    log_info(f"[GitHub Contributors] Fetching contributors for {owner}/{repo} at version {version}")
    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        contributors = {commit['commit']['author']['name'] for commit in response.json() if commit.get('commit')}
        return list(contributors)
    except requests.RequestException as e:
        log_error(f"[GitHub Contributors] Error fetching contributors for {owner}/{repo}@{version}: {e}")
        return []

def check_jitpack(group_id, artifact_id, version, token=None):
    """
    Checks the availability of an artifact in JitPack.
    """
    owner = group_id.split('.')[-1]  # Extract owner from group ID
    repo = artifact_id

    # Fetch tags (versions) from GitHub
    tags = fetch_github_tags(owner, repo, token)
    if tags is not None:
        normalized_tags = [normalize_version(tag) for tag in tags]
        if version in normalized_tags:
            artifact_url = f"{JITPACK_ARTIFACT_BASE_URL}/{owner}/{repo}/{version}/{artifact_id}-{version}.jar"
            log_info(f"[JitPack Check] Artifact found via GitHub tags: {artifact_url}")
            return artifact_url, JITPACK_BASE_URL
        log_warning(f"[JitPack Check] Version {version} not found in GitHub tags for {owner}/{repo}. Tags: {normalized_tags}")

    # Fallback to HTTP HEAD checks
    artifact_base_path = f"{JITPACK_ARTIFACT_BASE_URL}/{owner}/{repo}/{version}/{artifact_id}-{version}"
    extensions = ["jar", "aar", "pom", "module"]

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        try:
            response = requests.head(artifact_url, timeout=10)
            if response.status_code == 200:
                log_info(f"[JitPack Check] Found artifact at: {artifact_url}")
                return artifact_url, JITPACK_BASE_URL
        except requests.RequestException as e:
            log_error(f"[JitPack Check] Error accessing URL {artifact_url}: {e}")

    log_warning(f"[JitPack Check] Artifact not found in JitPack: {group_id}:{artifact_id}:{version}")
    return None, None

def normalize_version(version):
    """
    Normalizes a version string by removing any common prefixes like 'v'.
    """
    return version.lstrip("v").strip()

def fetch_versions_from_git_tags_via_jitpack(group_id, artifact_id, token=""):
    """
    Fetches available versions from GitHub tags used by JitPack.
    Args:
        group_id (str): The group ID of the artifact.
        artifact_id (str): The artifact ID.
        token (str, optional): GitHub personal access token for authenticated requests.
    Returns:
        list: A list of versions available in GitHub tags, or an empty list if not found.
    """
    owner = group_id.split('.')[-1]  # Extract owner from group ID
    repo = artifact_id

    tags = fetch_github_tags(owner, repo, token)
    if tags is not None:
        log_info(f"[JitPack Version Fetch] Found versions in GitHub tags for {group_id}:{artifact_id}: {tags}")
        return tags
    else:
        log_warning(f"[JitPack Version Fetch] No GitHub tags found for {group_id}:{artifact_id}")
        return []
    

def fetch_github_contributors(owner, repo, version, token=""):
    """
    Получает список контрибьюторов для конкретной версии репозитория на GitHub.
    Args:
        owner (str): Владелец репозитория (e.g., 'owner').
        repo (str): Название репозитория.
        version (str): Тег или версия, для которой нужно получить контрибьюторов.
        token (str, optional): GitHub API токен.

    Returns:
        list: Список контрибьюторов (логины).
    """
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": version}

    log_info(f"[GitHub Contributors] Fetching contributors for {owner}/{repo} at version {version}")
    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        contributors = {commit['commit']['author']['name'] for commit in response.json() if commit.get('commit')}
        return list(contributors)
    except requests.RequestException as e:
        log_error(f"[GitHub Contributors] Error fetching contributors for {owner}/{repo}@{version}: {e}")
        return []