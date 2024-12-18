import requests
from requests.exceptions import RequestException
from utils.logging import log_info, log_warning, log_error

def check_repository(group_id, artifact_id, version):
    """
    Checks if the artifact exists in Sonatype Central repository.
    Supports multiple file extensions like .jar, .aar, and .pom.

    :param group_id: Group ID of the artifact.
    :param artifact_id: Artifact ID.
    :param version: Version of the artifact.
    :return: Tuple of artifact URL and base repository URL if found, otherwise (None, None).
    """
    base_url = "https://repo1.maven.org/maven2"
    artifact_base_path = f"{base_url}/{group_id.replace('.', '/')}/{artifact_id}/{version}/{artifact_id}-{version}"

    # List of supported extensions
    extensions = ["jar", "aar", "pom"]
    timeout = 10

    for ext in extensions:
        artifact_url = f"{artifact_base_path}.{ext}"
        try:
            response = requests.head(artifact_url, timeout=timeout)
            if response.status_code == 200:
                log_info(f"[Sonatype Central] Found artifact: {artifact_url}")
                return artifact_url, base_url
            elif response.status_code == 404:
                log_info(f"[Sonatype Central] Artifact not found: {artifact_url}")
            else:
                log_warning(f"[Sonatype Central] Unexpected status {response.status_code} for {artifact_url}")
        except RequestException as e:
            log_error(f"[Sonatype Central] Error accessing {artifact_url}: {e}")

    log_warning(f"[Sonatype Central] Artifact not found in repository: {group_id}:{artifact_id}:{version}")
    return None, None
