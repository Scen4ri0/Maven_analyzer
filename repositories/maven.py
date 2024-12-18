import requests
from requests.exceptions import RequestException
from utils.logging import log_info, log_warning, log_error

def check_maven(group_id, artifact_id, version):
    """
    Checks for the presence of an artifact in Maven Central.
    Returns the URL of the artifact and the base repository URL if found.
    """
    base_repository_url = "https://repo1.maven.org/maven2"
    artifact_base_path = f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    # List of supported extensions
    extensions = ["jar", "aar", "pom"]
    timeout = 10

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        try:
            response = requests.head(artifact_url, timeout=timeout)
            if response.status_code == 200:
                log_info(f"[Maven Check] Artifact found: {artifact_url}")
                return artifact_url, base_repository_url
            elif response.status_code == 404:
                log_info(f"[Maven Check] Artifact not found: {artifact_url}")
            else:
                log_warning(f"[Maven Check] Unexpected status {response.status_code} for URL: {artifact_url}")
        except RequestException as e:
            log_error(f"[Maven Check] Error checking artifact {artifact_url}: {e}")

    log_warning("[Maven Check] Artifact not found in Maven Central.")
    return None, base_repository_url
