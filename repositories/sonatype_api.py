import requests
from utils.logging import log_error, log_warning

SONATYPE_API_BASE = "https://search.maven.org/solrsearch/select"

def get_latest_versions_sonatype_api(group_id, artifact_id, max_versions=5):
    """
    Retrieves the latest versions of a library using Sonatype Central API,
    including available extension types.
    """
    try:
        query = f"g:{group_id} AND a:{artifact_id}"
        params = {
            "q": query,
            "rows": max_versions,
            "core": "gav",
            "wt": "json",
            "sort": "version desc",
        }
        response = requests.get(SONATYPE_API_BASE, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        versions_info = [
            {
                "version": doc["v"],
                "extensions": doc.get("ec", [])  # Get available extensions
            }
            for doc in data["response"]["docs"]
        ]
        if not versions_info:
            log_warning(f"[Sonatype API] No versions found via Sonatype API for {group_id}:{artifact_id}.")
        return versions_info[:max_versions]
    except Exception as e:
        log_error(f"[Sonatype API] Error retrieving versions for {group_id}:{artifact_id}: {e}")
        return []
