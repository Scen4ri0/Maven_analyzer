# domain/domain_utils.py
import whois
from datetime import datetime

import requests
from utils.logging import log_info, log_warning, log_error
from tenacity import retry, stop_after_attempt, wait_exponential
from dateutil import parser
from datetime import timezone
from domain.domain_info import get_domain_info


def group_id_to_domain(group_id):
    """
    Converts a Maven group ID to a domain.
    Extracts the second-to-last and last parts as the domain.
    """
    parts = group_id.split('.')
    if len(parts) >= 2:
        domain_name = f"{parts[1]}.{parts[0]}"  # Извлекаем два последних уровня
    else:
        domain_name = group_id  # Если частей меньше двух, возвращаем как есть

    log_info(f"[Domain Conversion] Converted group ID '{group_id}' to domain '{domain_name}'.")
    return domain_name

def is_domain_available(domain):
    """
    Checks if a domain is available for purchase using WHOIS.
    Marks as vulnerable if the domain is not found or WHOIS fails.
    """
    try:
        whois_info = whois.whois(domain)
        # If WHOIS response has no status or indicates it's not found, mark as vulnerable
        if not whois_info or not whois_info.status:
            log_warning(f"[Domain Check] Domain '{domain}' not found or no status available. Marking as VULNERABLE.")
            return True  # Domain is vulnerable
        log_info(f"[Domain Check] Domain '{domain}' is registered.")
        return False  # Domain is registered
    except Exception as e:
        log_warning(f"[Domain Check] WHOIS lookup failed for domain '{domain}': {e}. Marking as VULNERABLE.")
        return True  # Default to vulnerable if WHOIS fails

import requests
from datetime import datetime
from utils.logging import log_info, log_warning, log_error
from tenacity import retry, stop_after_attempt, wait_exponential


SECURITY_TRAILS_API_KEY = ""
SECURITY_TRAILS_BASE_URL = "https://api.securitytrails.com/v1/domain"

def group_id_to_domain(group_id):
    """
    Converts a Maven group ID to a domain.
    Extracts the second-to-last and last parts as the domain.
    """
    parts = group_id.split('.')
    if len(parts) >= 2:
        domain_name = f"{parts[1]}.{parts[0]}"  # Извлекаем два последних уровня
    else:
        domain_name = group_id  # Если частей меньше двух, возвращаем как есть

    log_info(f"[Domain Conversion] Converted group ID '{group_id}' to domain '{domain_name}'.")
    return domain_name


def is_domain_available(domain):
    """
    Checks if a domain is available for purchase using WHOIS.
    Marks as vulnerable if the domain is not found or WHOIS fails.
    """
    try:
        whois_info = whois.whois(domain)
        # If WHOIS response has no status or indicates it's not found, mark as vulnerable
        if not whois_info or not whois_info.status:
            log_warning(f"[Domain Check] Domain '{domain}' not found or no status available. Marking as VULNERABLE.")
            return True  # Domain is vulnerable
        log_info(f"[Domain Check] Domain '{domain}' is registered.")
        return False  # Domain is registered
    except Exception as e:
        log_warning(f"[Domain Check] WHOIS lookup failed for domain '{domain}': {e}. Marking as VULNERABLE.")
        return True  # Default to vulnerable if WHOIS fails


def is_recently_updated(domain):
    """
    Проверяет, был ли домен зарегистрирован или обновлен с начала 2024 года.
    """
    try:
        domain_info = get_domain_info(domain)
        if not domain_info:
            return {"domain": domain, "recently_updated": False, "reason": "No WHOIS data available"}

        recent_date_threshold = datetime(2024, 1, 1)
        creation_date = domain_info.get("creation_date")
        updated_date = domain_info.get("updated_date")

        # Проверяем дату создания и обновления
        recently_updated = (
            (creation_date and creation_date >= recent_date_threshold) or
            (updated_date and updated_date >= recent_date_threshold)
        )

        if recently_updated:
            log_info(f"[Domain Check] Domain '{domain}' was recently updated or created.")
            return {"domain": domain, "recently_updated": True, "creation_date": creation_date, "updated_date": updated_date}

        log_info(f"[Domain Check] Domain '{domain}' has no recent updates.")
        return {"domain": domain, "recently_updated": False, "creation_date": creation_date, "updated_date": updated_date}
    except Exception as e:
        log_error(f"[Domain Check] Error checking recent updates for domain '{domain}': {e}")
        return {"domain": domain, "recently_updated": False, "error": str(e)}