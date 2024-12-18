import requests
from requests.exceptions import RequestException
from utils.logging import log_info, log_warning, log_error

def check_sonatype(group_id, artifact_id, version):
    """
    Checks the availability of an artifact in Sonatype.
    """
    base_repository_url = "https://s01.oss.sonatype.org/content/repositories/releases"
    artifact_base_path = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    extensions = ["jar", "aar", "pom"]

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        try:
            response = requests.head(artifact_url, timeout=10)
            if response.status_code == 200:
                log_info(f"[Sonatype] Found artifact: {artifact_url}")
                return artifact_url, base_repository_url
            elif response.status_code == 404:
                log_info(f"[Sonatype] Artifact not found: {artifact_url}")
            else:
                log_warning(f"[Sonatype] Unexpected status code {response.status_code} for URL: {artifact_url}")
        except requests.RequestException as e:
            log_error(f"[Sonatype] Error checking {artifact_url}: {e}")
    return None, None
