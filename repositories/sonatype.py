import aiohttp
from utils.logging import log_info, log_warning, log_error


async def check_sonatype(group_id, artifact_id, version):
    """
    Checks the availability of an artifact in Sonatype asynchronously.
    """
    base_repository_url = "https://s01.oss.sonatype.org/content/repositories/releases"
    artifact_base_path = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    extensions = ["jar", "aar", "pom"]

    async with aiohttp.ClientSession() as session:
        for ext in extensions:
            artifact_url = f"{artifact_base_path}.{ext}"
            try:
                async with session.head(artifact_url, timeout=10) as response:
                    if response.status == 200:
                        log_info(f"[Sonatype] Found artifact: {artifact_url}")
                        return artifact_url, base_repository_url
                    elif response.status == 404:
                        log_info(f"[Sonatype] Artifact not found: {artifact_url}")
                    else:
                        log_warning(f"[Sonatype] Unexpected status code {response.status} for URL: {artifact_url}")
            except aiohttp.ClientError as e:
                log_error(f"[Sonatype] Error checking {artifact_url}: {e}")
    return None, None
