# domain/domain_info.py
import whois
from datetime import datetime
from utils.logging import log_error, log_info


def get_domain_info(domain):
    """
    Получает информацию о домене, включая дату создания и обновления.
    """
    try:
        w = whois.whois(domain)
        creation_date = None
        updated_date = None

        # Обрабатываем дату создания
        if w.creation_date:
            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date, "%Y-%m-%d")

        # Обрабатываем дату обновления
        if w.updated_date:
            updated_date = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date
            if isinstance(updated_date, str):
                updated_date = datetime.strptime(updated_date, "%Y-%m-%d")

        return {"creation_date": creation_date, "updated_date": updated_date}
    except whois.parser.PywhoisError:
        log_info(f"[Domain Info] Domain '{domain}' is available for registration.")
        return None  # Домен доступен для регистрации
    except Exception as e:
        log_error(f"[Domain Info] Error retrieving WHOIS info for {domain}: {e}")
        return None
