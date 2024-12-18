import requests
from requests.exceptions import RequestException
from utils.logging import log_info, log_warning, log_error

def check_springio(group_id, artifact_id, version):
    """
    Checks the availability of an artifact in SpringIO.
    """
    base_repository_url = "https://repo.spring.io/release"
    artifact_base_path = (
        f"{base_repository_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"
    ).strip()

    extensions = ["jar", "aar", "pom"]

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        try:
            response = requests.head(artifact_url, timeout=10)
            if response.status_code == 200:
                log_info(f"[Spring IO Check] Found artifact at: {artifact_url}")
                return artifact_url, base_repository_url
            elif response.status_code == 401:
                log_warning(f"[Spring IO Check] Authentication required for URL: {artifact_url}")
            elif response.status_code == 404:
                log_info(f"[Spring IO Check] File not found: {artifact_url}")
            else:
                log_warning(f"[Spring IO Check] Unexpected status code {response.status_code} for URL: {artifact_url}")
        except requests.RequestException as e:
            log_error(f"[Spring IO Check] Error accessing URL {artifact_url}: {e}")
    return None, None
