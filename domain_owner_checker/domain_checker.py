import json
import requests
from datetime import datetime

API_KEY = ""  # Замените на ваш API-ключ SecurityTrails
API_URL = "https://api.securitytrails.com/v1/history/{}/whois"


def fetch_whois_history(domain):
    """
    Запрашивает историю WHOIS для домена через SecurityTrails API.
    """
    headers = {"APIKEY": API_KEY}
    try:
        response = requests.get(API_URL.format(domain), headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"[Error] Failed to fetch WHOIS history for {domain}: {e}")
        return None

def parse_whois_history(whois_history):
    """
    Парсит историю WHOIS для анализа владельца.
    """
    records = whois_history.get("result", {}).get("items", [])
    if not records:
        return [], None

    parsed_records = []
    for record in records:
        if "started" in record and "contact" in record:
            started = datetime.fromtimestamp(record["started"] / 1000)
            parsed_records.append({"year": started.year, "data": record})

    return parsed_records

def compare_records(record1, record2):
    """
    Сравнивает две записи WHOIS по владельцу.
    """
    # Проверяем, что записи не пустые и корректного формата
    if not record1 or not isinstance(record1, dict):
        return "ERROR", "Invalid record1 format or empty data."
    if not record2 or not isinstance(record2, dict):
        return "ERROR", "Invalid record2 format or empty data."

    contact1 = record1.get("data", {}).get("contact", [])
    contact2 = record2.get("data", {}).get("contact", [])

    if not isinstance(contact1, list) or not isinstance(contact2, list):
        return "ERROR", "Invalid contact data structure. Expected lists."

    # Логика сравнения
    changes = []
    date1 = datetime.fromtimestamp(record1["data"]["started"] / 1000).strftime("%Y-%m-%d")
    date2 = datetime.fromtimestamp(record2["data"]["started"] / 1000).strftime("%Y-%m-%d")

    for contact1_entry, contact2_entry in zip(contact1, contact2):
        if not isinstance(contact1_entry, dict) or not isinstance(contact2_entry, dict):
            continue  # Пропускаем некорректные данные

        field_changes = {}
        for field in ["name", "email", "organization", "city", "country", "state", "telephone"]:
            pre_value = contact1_entry.get(field, "N/A")
            post_value = contact2_entry.get(field, "N/A")
            if pre_value != post_value:
                field_changes[field] = {
                    "before": pre_value,
                    "after": post_value,
                }

        if field_changes:
            changes.append({
                "field_changes": field_changes,
                "record_1_date": date1,
                "record_2_date": date2,
            })

    if changes:
        return "CHANGED", changes
    return "OK", "No owner changes detected."

def analyze_domain(domain, full_responses):
    """
    Анализирует домен на смену владельца за 2024 год.
    """
    whois_history = fetch_whois_history(domain)
    if whois_history:
        full_responses[domain] = whois_history  # Сохраняем полный ответ API
    else:
        return {"domain": domain, "status": "ERROR", "reason": "Failed to fetch WHOIS data"}

    records = parse_whois_history(whois_history)

    if not records:
        return {"domain": domain, "status": "UNKNOWN", "reason": "No WHOIS records available"}

    if len(records) == 1:
        return {
            "domain": domain,
            "status": "OK",
            "reason": "Only one WHOIS record available, assuming no owner change",
            "year": records[0]["year"],
        }

    # Сравнение всех доступных записей
    first_record = records[0]
    last_record = records[-1]
    status, reason = compare_records(first_record, last_record)

    if status == "CHANGED":
        change_years = [change["record_2_date"] for change in reason]
        if "2024" in ''.join(change_years):
            return {
                "domain": domain,
                "status": status,
                "reason": "Owner contact details changed in 2024.",
                "details": reason,
            }
        return {
            "domain": domain,
            "status": "OK",
            "reason": "No owner changes detected in 2024.",
        }

    return {
        "domain": domain,
        "status": status,
        "reason": reason,
    }

def process_domains(file_path, full_responses):
    """
    Читает файл с доменами и анализирует их.
    """
    try:
        with open(file_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[Error] File not found: {file_path}")
        return []

    results = []
    for domain in domains:
        print(f"[Info] Analyzing domain: {domain}")
        result = analyze_domain(domain, full_responses)
        results.append(result)
        print(f"[Result] {json.dumps(result, indent=2)}")  # Дублируем результат в консоль
    return results

def save_results(results, full_responses, output_file="results.json", responses_file="full_responses.json"):
    """
    Сохраняет результаты анализа и полные ответы API в файлы.
    """
    try:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[Info] Results saved to {output_file}")

        with open(responses_file, "w") as f:
            json.dump(full_responses, f, indent=4)
        print(f"[Info] Full API responses saved to {responses_file}")
    except Exception as e:
        print(f"[Error] Failed to save results: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Check domain owner change.")
    parser.add_argument("input_file", help="Path to the file containing domains.")
    parser.add_argument("-o", "--output", default="results.json", help="Output file for results.")
    parser.add_argument("-r", "--responses", default="full_responses.json", help="File to save full API responses.")
    args = parser.parse_args()

    full_responses = {}
    results = process_domains(args.input_file, full_responses)
    save_results(results, full_responses, args.output, args.responses)