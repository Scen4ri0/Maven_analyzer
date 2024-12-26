import whois
from datetime import datetime
from utils.logging import log_error, log_info


def parse_date(date_value):
    """
    Универсальный парсер для дат из WHOIS-записей.
    """
    if isinstance(date_value, list):
        date_value = date_value[0]
    if isinstance(date_value, str):
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%d-%m-%Y"):
            try:
                return datetime.strptime(date_value, fmt)
            except ValueError:
                continue
    return date_value  # Вернуть оригинальное значение, если это datetime или None


def get_domain_info(domain):
    """
    Получает информацию о домене, включая дату создания, обновления, регистратора и статус.
    """
    try:
        w = whois.whois(domain)

        # Обрабатываем даты
        creation_date = parse_date(w.creation_date)
        updated_date = parse_date(w.updated_date)

        if not creation_date:
            log_info(f"[Domain Info] No creation date found for domain '{domain}'.")
        if not updated_date:
            log_info(f"[Domain Info] No updated date found for domain '{domain}'.")

        return {
            "creation_date": creation_date,
            "updated_date": updated_date,
            "registrar": w.registrar if hasattr(w, 'registrar') else None,
            "status": w.status if hasattr(w, 'status') else None
        }
    except Exception as e:
        if "No match for domain" in str(e):
            log_info(f"[Domain Info] Domain '{domain}' is available for registration.")
            return None
        log_error(f"[Domain Info] Error retrieving WHOIS info for {domain}: {e}")
        return None
