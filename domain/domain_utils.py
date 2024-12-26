import whois
from datetime import datetime, timezone
from utils.logging import log_info, log_warning, log_error
from domain.domain_info import get_domain_info


def group_id_to_domain(group_id):
    """
    Converts a Maven group ID to a domain.
    Extracts the second-to-last and last parts as the domain.
    """
    parts = group_id.split('.')
    if len(parts) >= 2:
        domain_name = f"{parts[1]}.{parts[0]}"
    else:
        domain_name = group_id

    log_info(f"[Domain Conversion] Converted group ID '{group_id}' to domain '{domain_name}'.")
    return domain_name


def is_domain_available(domain):
    """
    Checks if a domain is available for purchase using WHOIS.
    Marks as vulnerable if the domain is not found or WHOIS fails.
    """
    try:
        whois_info = whois.whois(domain)
        if not whois_info:
            log_warning(f"[Domain Check] No WHOIS information for domain '{domain}'. Marking as VULNERABLE.")
            return True

        if not hasattr(whois_info, "status") or not whois_info.status:
            log_warning(f"[Domain Check] Domain '{domain}' has no WHOIS status. Marking as VULNERABLE.")
            return True

        log_info(f"[Domain Check] Domain '{domain}' is registered with status: {whois_info.status}.")
        return False
    except Exception as e:
        log_warning(f"[Domain Check] WHOIS lookup failed for domain '{domain}': {e}. Marking as VULNERABLE.")
        return True


def is_recently_updated(domain):
    """
    Checks if the domain was registered or updated since the beginning of 2024.
    """
    try:
        domain_info = get_domain_info(domain)
        if not domain_info:
            return {"domain": domain, "recently_updated": False, "reason": "No WHOIS data available"}

        recent_date_threshold = datetime(2024, 1, 1, tzinfo=timezone.utc)
        creation_date = domain_info.get("creation_date")
        updated_date = domain_info.get("updated_date")

        if creation_date and creation_date >= recent_date_threshold:
            log_info(f"[Domain Check] Domain '{domain}' was created recently on {creation_date}.")
            return {
                "domain": domain,
                "recently_updated": True,
                "creation_date": creation_date,
                "updated_date": updated_date
            }
        if updated_date and updated_date >= recent_date_threshold:
            log_info(f"[Domain Check] Domain '{domain}' was updated recently on {updated_date}.")
            return {
                "domain": domain,
                "recently_updated": True,
                "creation_date": creation_date,
                "updated_date": updated_date
            }

        log_info(f"[Domain Check] Domain '{domain}' has no recent updates.")
        return {
            "domain": domain,
            "recently_updated": False,
            "creation_date": creation_date,
            "updated_date": updated_date
        }
    except Exception as e:
        log_error(f"[Domain Check] Error checking recent updates for domain '{domain}': {e}")
        return {"domain": domain, "recently_updated": False, "error": str(e)}
