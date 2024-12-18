import requests
import xml.etree.ElementTree as ET
from utils.logging import log_info, log_warning, log_error
from repositories.sonatype_api import get_latest_versions_sonatype_api
import re

def parse_version(version):
    """
    Parses a version string into a tuple suitable for sorting.
    Handles numeric and pre-release versions.
    """
    try:
        parts = version.split("-")
        numeric_part = tuple(int(x) for x in parts[0].split("."))
        pre_release = parts[1] if len(parts) > 1 else ""
        return numeric_part, pre_release
    except ValueError:
        log_warning(f"[Version Parsing] Unable to parse version: {version}")
        # Return a fallback value to ensure consistency
        return (float('-inf'), "")

def compare_versions(v1, v2):
    """
    Compares two parsed version tuples (numeric_part, pre_release).
    Handles numeric and pre-release parts.
    """
    numeric1, pre1 = parse_version(v1)
    numeric2, pre2 = parse_version(v2)

    # Compare numeric parts
    if numeric1 != numeric2:
        return (numeric1 > numeric2) - (numeric1 < numeric2)

    # Compare pre-release tags: Empty string (stable) > any pre-release
    if pre1 == pre2:
        return 0
    if not pre1:  # v1 is stable
        return 1
    if not pre2:  # v2 is stable
        return -1
    return (pre1 > pre2) - (pre1 < pre2)  # Lexicographic comparison

def get_latest_versions(group_id, artifact_id, start_version, max_versions, base_url, use_sonatype_api=False):
    """
    Fetches versions relative to a specified start version.
    Handles both numeric and pre-release versions.
    """
    if use_sonatype_api:
        log_info(f"[Version Management] Using Sonatype API to fetch versions for {group_id}:{artifact_id}.")
        versions_info = get_latest_versions_sonatype_api(group_id, artifact_id, max_versions + 1)
        versions = [v["version"] for v in versions_info]
    else:
        metadata_url = f"{base_url}/{group_id.replace('.', '/')}/{artifact_id}/maven-metadata.xml"
        try:
            response = requests.get(metadata_url, timeout=10)
            if response.status_code != 200:
                log_warning(f"[Version Management] Failed to fetch metadata from {metadata_url}")
                return []

            root = ET.fromstring(response.text)
            versions = [v.text for v in root.findall(".//version")]
        except Exception as e:
            log_error(f"[Version Management] Error fetching versions: {e}")
            return []

    # Sort versions with pre-release handling
    sorted_versions = sorted(versions, key=parse_version, reverse=True)
    parsed_start_version = parse_version(start_version)

    # Filter for versions strictly preceding the start_version
    preceding_versions = [
        v for v in sorted_versions if compare_versions(v, start_version) < 0
    ]

    # Return up to max_versions
    return preceding_versions[:max_versions]


