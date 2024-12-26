import aiohttp
from utils.logging import log_info, log_warning, log_error

async def check_jboss(group_id, artifact_id, version):
    """
    Checks the presence of an artifact in the JBoss repository and returns the artifact URL and base repository URL.
    Supports checking artifacts with different extensions asynchronously.
    """
    base_repository_url = "https://repository.jboss.org/nexus/content/repositories/public"
    artifact_base_path = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    # Supported extensions
    extensions = ["jar", "aar", "pom"]

    async with aiohttp.ClientSession() as session:
        for ext in extensions:
            artifact_url = f"{artifact_base_path}.{ext}"
            try:
                async with session.head(artifact_url, timeout=10) as response:
                    if response.status == 200:
                        log_info(f"[JBoss Check] Found artifact at: {artifact_url}")
                        return artifact_url, base_repository_url
                    elif response.status == 404:
                        log_info(f"[JBoss Check] Artifact not found: {artifact_url}")
                    else:
                        log_warning(f"[JBoss Check] Unexpected status code {response.status} for URL: {artifact_url}")
            except aiohttp.ClientError as e:
                log_error(f"[JBoss Check] Error accessing URL {artifact_url}: {e}")

    log_warning(f"[JBoss Check] No valid artifact found for {group_id}:{artifact_id}:{version} in JBoss.")
    return None, None
