import aiohttp
from utils.logging import log_warning, log_error, log_info

# Define constants for JitPack and GitHub
JITPACK_BASE_URL = "https://jitpack.io"
JITPACK_ARTIFACT_BASE_URL = f"{JITPACK_BASE_URL}/com/github"
GITHUB_TAGS_API_URL = "https://api.github.com/repos"


async def fetch_github_tags(owner, repo, token=None):
    """
    Fetches tags (versions) for a given GitHub repository using the GitHub API asynchronously.
    """
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = f"{GITHUB_TAGS_API_URL}/{owner}/{repo}/tags"
    log_info(f"[GitHub API] Querying tags for {owner}/{repo} at {api_url}")

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(api_url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    tags_data = await response.json()
                    tags = [normalize_version(tag["name"]) for tag in tags_data]
                    log_info(f"[GitHub API] Found tags for {owner}/{repo}: {tags}")
                    return tags
                else:
                    log_warning(f"[GitHub API] Unexpected status {response.status} for {api_url}")
        except aiohttp.ClientError as e:
            log_error(f"[GitHub API] Error fetching tags for {owner}/{repo}: {e}")
    return None


async def fetch_github_contributors(owner, repo, version, token=None, session=None):
    if session is None:
        raise ValueError("[GitHub Contributors] Session is not initialized")
    
    headers = {"Authorization": f"token {token}"} if token else {}
    api_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"sha": version}

    log_info(f"[GitHub Contributors] Fetching contributors for {owner}/{repo} at version {version}")
    try:
        async with session.get(api_url, headers=headers, params=params, timeout=10) as response:
            if response.status == 200:
                commits = await response.json()
                contributors = {
                    commit['commit']['author']['name']
                    for commit in commits if commit.get('commit')
                }
                return list(contributors)
            else:
                log_warning(f"[GitHub Contributors] Unexpected status {response.status} for {api_url}")
    except aiohttp.ClientError as e:
        log_error(f"[GitHub Contributors] Error fetching contributors for {owner}/{repo}@{version}: {e}")
    return []



async def check_jitpack(group_id, artifact_id, version, token=None):
    """
    Checks the availability of an artifact in JitPack asynchronously.
    """
    owner = group_id.split('.')[-1]  # Extract owner from group ID
    repo = artifact_id

    # Fetch tags (versions) from GitHub
    tags = await fetch_github_tags(owner, repo, token)
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

    async with aiohttp.ClientSession() as session:
        for ext in extensions:
            artifact_url = f"{artifact_base_path}.{ext}"
            try:
                async with session.head(artifact_url, timeout=10) as response:
                    if response.status == 200:
                        log_info(f"[JitPack Check] Found artifact at: {artifact_url}")
                        return artifact_url, JITPACK_BASE_URL
            except aiohttp.ClientError as e:
                log_error(f"[JitPack Check] Error accessing URL {artifact_url}: {e}")

    log_warning(f"[JitPack Check] Artifact not found in JitPack: {group_id}:{artifact_id}:{version}")
    return None, None


def normalize_version(version):
    """
    Normalizes a version string by removing any common prefixes like 'v'.
    """
    return version.lstrip("v").strip()


async def fetch_versions_from_git_tags_via_jitpack(group_id, artifact_id, token=""):
    """
    Fetches available versions from GitHub tags used by JitPack asynchronously.

    Args:
        group_id (str): The group ID of the artifact.
        artifact_id (str): The artifact ID.
        token (str, optional): GitHub personal access token for authenticated requests.

    Returns:
        list: A list of versions available in GitHub tags, or an empty list if not found.
    """
    owner = group_id.split('.')[-1]  # Extract owner from group ID
    repo = artifact_id

    tags = await fetch_github_tags(owner, repo, token)
    if tags is not None:
        log_info(f"[JitPack Version Fetch] Found versions in GitHub tags for {group_id}:{artifact_id}: {tags}")
        return tags
    else:
        log_warning(f"[JitPack Version Fetch] No GitHub tags found for {group_id}:{artifact_id}")
        return []
