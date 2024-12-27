import aiohttp
import asyncio
from utils.logging import log_info, log_warning, log_error

API_URL = "https://www.virustotal.com/api/v3/files"
REPORT_URL = "https://www.virustotal.com/api/v3/analyses"

def validate_api_key(api_key):
    """
    Проверяет, что API-ключ передан корректно.
    """
    if not api_key:
        raise ValueError("[VirusTotal] API key is required.")
    return {"x-apikey": api_key}

async def scan_file(file_path, api_key):
    """
    Отправляет файл в VirusTotal для анализа.
    """
    headers = validate_api_key(api_key)
    try:
        log_info(f"[VirusTotal] Preparing to scan file: {file_path}")
        async with aiohttp.ClientSession() as session:
            with open(file_path, "rb") as file:
                form_data = aiohttp.FormData()
                form_data.add_field("file", file, filename=file_path)
                log_info("[VirusTotal] Sending file for scanning...")
                async with session.post(API_URL, data=form_data, headers=headers) as response:
                    response_data = await response.json()
                    log_info(f"[VirusTotal] Response status: {response.status}")
                    if response.status == 200:
                        log_info(f"[VirusTotal] Scan successful: {response_data}")
                        return response_data
                    log_warning(f"[VirusTotal] Scan failed: {response_data}")
                    return {"error": response_data.get("error", "Unknown error")}
    except Exception as e:
        log_error(f"[VirusTotal] Error scanning file: {e}")
        return {"error": str(e)}

async def get_report(analysis_id, api_key):
    """
    Получает отчёт из VirusTotal по analysis_id.
    """
    headers = validate_api_key(api_key)
    url = f"{REPORT_URL}/{analysis_id}"
    try:
        log_info(f"[VirusTotal] Requesting report for analysis_id: {analysis_id}")
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                response_data = await response.json()
                log_info(f"[VirusTotal] Response status: {response.status}")
                if response.status == 200:
                    log_info(f"[VirusTotal] Report retrieved: {response_data}")
                    return response_data
                log_warning(f"[VirusTotal] Report retrieval failed: {response_data}")
                return {"error": response_data.get("error", "Unknown error")}
    except Exception as e:
        log_error(f"[VirusTotal] Error retrieving report: {e}")
        return {"error": str(e)}

async def analyze_in_sandbox(file_path, api_key):
    """
    Анализ файла в песочнице VirusTotal (без повторных попыток).
    """
    # Отправляем файл в VirusTotal
    scan_result = await scan_file(file_path, api_key)
    if "error" in scan_result:
        log_error(f"[VirusTotal] Error during scan: {scan_result['error']}")
        return {"error": f"Failed to scan file: {scan_result['error']}"}

    analysis_id = scan_result.get("data", {}).get("id")
    if not analysis_id:
        log_error("[VirusTotal] Analysis ID not found in response.")
        return {"error": "Analysis ID not found in VirusTotal response."}

    # Единственный запрос отчёта
    log_info(f"[VirusTotal] Fetching report for analysis ID: {analysis_id}")
    report = await get_report(analysis_id, api_key)

    # Возвращаем результат независимо от статуса
    status = report.get("data", {}).get("attributes", {}).get("status", "unknown")
    log_info(f"[VirusTotal] Report status: {status}")
    return report
