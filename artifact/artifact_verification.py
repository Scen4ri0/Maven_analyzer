import asyncio
from datetime import datetime
from artifact.artifact_status import ArtifactStatus, calculate_risk
from artifact.signature_verification import compare_signatures_across_versions
from artifact.artifact_info import get_selected_versions, extract_publication_date
from utils.logging import log_info, log_warning, log_error
from domain.domain_utils import group_id_to_domain, is_domain_available, is_recently_updated, check_domain_status
from repositories.repositories import find_in_repositories, compare_contributors_across_versions, compare_versions_across_repositories
from datetime import datetime, timezone


async def process_artifact(artifact, check_domain=False, github_token=None):
    """
    Processes an artifact to verify its status across repositories, domain availability,
    version consistency, and signature verification. Also checks for contributor differences.

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

    # Проверка домена и обновлений
    if check_domain:
        tasks.append(check_domain_status(group_id))
        tasks.append(extract_publication_date(
            base_repository_url="https://repo1.maven.org/maven2",  # Укажите базовый URL
            group_id=group_id,
            artifact_id=artifact_id,
            version=version
        ))

    # Проверка репозиториев
    tasks.append(find_in_repositories(group_id, artifact_id, version))

    # Проверка подписей и контрибьюторов
    tasks.append(check_signatures_and_contributors(group_id, artifact_id, version, github_token))

    # Выполняем все задачи параллельно
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Обработка результата проверки домена
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

        # Обработка результата публикации
        publication_date_result = results[1]
        recent_threshold = datetime(2024, 1, 1, tzinfo=timezone.utc)
        if isinstance(publication_date_result, datetime):
            published_recently = publication_date_result >= recent_threshold
            log_info(f"[Publication Date] Artifact published recently: {published_recently}")
            result["published_recently"] = published_recently
        else:
            log_warning(f"[Publication Date] Could not determine publication date: {publication_date_result}")
            result["published_recently"] = False

    # Обработка результата проверки репозиториев
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

    # Обработка результата проверки подписей и контрибьюторов
    signature_and_contributors_result = results[3 if check_domain else 1]
    if isinstance(signature_and_contributors_result, tuple):
        signature_status, contributors_diff, version_differences, risk = signature_and_contributors_result
        result.update({
            "signature": signature_status.value,
            "contributors_diff": contributors_diff,
            "version_differences": version_differences,
            "risk": risk,
        })
    else:
        log_warning(f"[Signature/Contributor Check] Error occurred: {signature_and_contributors_result}")
        result.update({
            "version_differences": False,
            "signature": ArtifactStatus.NOT_SIGNED.value,
            "contributors_diff": False,
            "risk": "unknown",
        })

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

    risk = calculate_risk(version_differences, contributors_diff, signature_status)
    return signature_status, contributors_diff, version_differences, risk

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
