import asyncio
import aiohttp
import os
from datetime import datetime
from artifact.artifact_status import ArtifactStatus, calculate_risk
from artifact.signature_verification import compare_signatures_across_versions
from artifact.artifact_info import get_selected_versions, extract_publication_date
from utils.logging import log_info, log_warning, log_error
from utils.file_operations import save_file, clean_up_files
from domain.domain_utils import group_id_to_domain, is_domain_available, is_recently_updated, check_domain_status
from repositories.repositories import find_in_repositories, compare_contributors_across_versions, compare_versions_across_repositories
from datetime import datetime, timezone
from static_analysis.yara_analysis import load_yara_rules, scan_artifact_with_yara

async def download_artifact(group_id, artifact_id, version):
    """
    Downloads the artifact file (.jar or .aar) from Maven repository.

    Args:
        group_id (str): Group ID of the artifact.
        artifact_id (str): Artifact ID.
        version (str): Version of the artifact.

    Returns:
        str: Path to the downloaded file or None if download failed.
    """
    base_url = f"https://repo1.maven.org/maven2/{group_id.replace('.', '/')}/{artifact_id}/{version}/"
    file_types = ["jar", "aar"]
    for file_type in file_types:
        file_name = f"{artifact_id}-{version}.{file_type}"
        url = f"{base_url}{file_name}"
        log_info(f"[Download] Attempting to download: {url}")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        file_path = os.path.join(os.getcwd(), file_name)
                        content = await response.read()
                        save_file(file_path, content)
                        log_info(f"[Download] Successfully downloaded: {file_path}")
                        return file_path
                    else:
                        log_warning(f"[Download] {file_name} not found (status: {response.status}). Trying next file type.")
        except Exception as e:
            log_error(f"[Download] Error downloading file {file_name}: {e}")
    
    log_warning("[Download] Failed to download artifact file. Both .jar and .aar not found.")
    return None


async def process_artifact(artifact, check_domain=False, github_token=None):
    """
    Processes an artifact to verify its status across repositories, domain availability,
    version consistency, signature verification, contributor analysis, and YARA static analysis.

    Args:
        artifact (str): The artifact in the format group_id:artifact_id:version.
        check_domain (bool): Flag to enable domain and publication date checks.
        github_token (str, optional): GitHub token for authenticated requests.

    Returns:
        dict: A dictionary containing verification results for the artifact.
    """
    try:
        group_id, artifact_id, version = artifact.split(':')
    except ValueError:
        log_error(f"[Artifact Parsing] Invalid artifact format: {artifact}")
        return {"artifact": artifact, "error": "Invalid format"}

    log_info(f"[Processing] Start verification for artifact: {artifact}")

    result = {"artifact": artifact}
    tasks = []

    # Load YARA rules
    try:
        yara_rules = load_yara_rules("yara_rules/java_analysis_rules.yar")
    except Exception as e:
        log_error(f"[YARA] Failed to load rules: {e}")
        yara_rules = None

    # Download artifact file for analysis
    artifact_file = await download_artifact(group_id, artifact_id, version)

    # Domain and update checks
    if check_domain:
        tasks.append(check_domain_status(group_id))
        tasks.append(extract_publication_date(
            base_repository_url="https://repo1.maven.org/maven2",
            group_id=group_id,
            artifact_id=artifact_id,
            version=version
        ))

    # Repository checks
    tasks.append(find_in_repositories(group_id, artifact_id, version))

    # Signature and contributor checks
    tasks.append(check_signatures_and_contributors(group_id, artifact_id, version, github_token))

    # YARA analysis if the artifact file was downloaded
    if artifact_file and yara_rules:
        tasks.append(scan_artifact_with_yara(yara_rules, artifact_file))
    else:
        tasks.append(None)

    # Execute all tasks
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process domain check results
    if check_domain:
        domain_result = results[0]
        if isinstance(domain_result, tuple):
            domain_status, recently_updated = domain_result
            result.update({
                "domain": domain_status,
                "recently_updated": recently_updated,
            })
        else:
            log_warning(f"[Domain Check] Error occurred: {domain_result}")
            result.update({"domain": "error", "recently_updated": False})

        # Process publication date result
        publication_date_result = results[1]
        recent_threshold = datetime(2024, 1, 1, tzinfo=timezone.utc)
        if isinstance(publication_date_result, datetime):
            published_recently = publication_date_result >= recent_threshold
            log_info(f"[Publication Date] Artifact published recently: {published_recently}")
            result["published_recently"] = published_recently
        else:
            log_warning(f"[Publication Date] Could not determine publication date: {publication_date_result}")
            result["published_recently"] = False

    # Process repository check results
    repository_result = results[2 if check_domain else 0]
    if isinstance(repository_result, list) and repository_result:
        log_info(f"[Repository Check] Found in {len(repository_result)} repositories.")
        result["repositories_found"] = len(repository_result)
    else:
        log_warning(f"[Repository Check] Artifact '{artifact}' not found in any repository.")
        result.update({
            "repositories_found": 0,
            "version_differences": False,
            "signature": ArtifactStatus.NOT_FOUND.value,
            "contributors_diff": False,
            "risk": "low"
        })
        return result

    # Process signature and contributor check results
    signature_and_contributors_result = results[3 if check_domain else 1]
    if isinstance(signature_and_contributors_result, tuple):
        signature_status, contributors_diff, version_differences = signature_and_contributors_result
        result.update({
            "signature": signature_status.value,
            "contributors_diff": contributors_diff,
            "version_differences": version_differences,
        })
    else:
        log_warning(f"[Signature/Contributor Check] Error occurred: {signature_and_contributors_result}")
        result.update({
            "version_differences": False,
            "signature": ArtifactStatus.NOT_SIGNED.value,
            "contributors_diff": False,
        })

    # Process YARA analysis results
    yara_result = results[4 if check_domain else 2]
    yara_scan_matched = False
    if yara_result and isinstance(yara_result, dict):
        yara_scan_matched = bool(yara_result.get("matches"))
        result.update({"yara_analysis": yara_result})
        log_info(f"[YARA Analysis] Matches found: {yara_scan_matched}")
    else:
        log_warning(f"[YARA Analysis] Error occurred: {yara_result}")
        result["yara_analysis"] = {"matches": [], "error": "Failed to analyze"}

    # Calculate risk
    try:
        # Ensure signature_status is mapped back to ArtifactStatus if needed
        signature_status = ArtifactStatus[result.get("signature", "NOT_SIGNED").upper()]
        risk = calculate_risk(
            result.get("version_differences", False),
            result.get("contributors_diff", False),
            signature_status,
            yara_scan_matched
        )
        result["risk"] = risk
        log_info(f"[Risk Calculation] Risk level for artifact '{artifact}': {risk}")
    except Exception as e:
        log_error(f"[Risk Calculation] Error calculating risk for artifact '{artifact}': {e}")
        result["risk"] = "unknown"

    # Clean up downloaded files
    if artifact_file:
        clean_up_files(f"{artifact_id}-{version}")

    log_info(f"[Processing] Verification complete for artifact: {artifact}")
    return result



### Асинхронная проверка подписей и контрибьюторов
async def check_signatures_and_contributors(group_id, artifact_id, version, github_token):
    """
    Checks signatures, contributors, and calculates risk.
    """
    base_repository_url = f"https://repo1.maven.org/maven2"
    signature_status = await compare_signatures_across_versions(group_id, artifact_id, version, base_repository_url)
    version_comparison = await compare_versions_across_repositories(group_id, artifact_id, version)
    version_differences = len(version_comparison["differing_versions"]) > 0

    contributors_diff = False
    versions_to_check = await get_selected_versions(base_repository_url, group_id, artifact_id, version)
    if versions_to_check:
        differences = await compare_contributors_across_versions(group_id.split(".")[-1], artifact_id, versions_to_check, github_token)
        contributors_diff = bool(differences)

    return signature_status, contributors_diff, version_differences

async def check_domain_status(group_id):
    """
    Checks the domain availability and recent updates.
    """
    domain = group_id_to_domain(group_id)
    log_info(f"[Domain Check] Checking domain: {domain}")
    
    try:
        domain_status = "vulnerable" if is_domain_available(domain) else "ok"
        recent_update = is_recently_updated(domain)
        
        if recent_update.get("error"):
            log_warning(f"[Domain Check] Error checking updates: {recent_update['error']}")
            recent_update_status = False
        else:
            recent_update_status = recent_update.get("recently_updated", False)

        return domain_status, recent_update_status

    except Exception as e:
        log_error(f"[Domain Check] Unexpected error for domain '{domain}': {e}")
        return "error", False