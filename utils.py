import requests
import time
import whois
from config import URLSCAN_API_KEY


def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        whois_text = f"Domain: {domain}\n"
        if w.registrar:
            whois_text += f"Registrar: {w.registrar}\n"
        if w.creation_date:
            whois_text += f"Creation Date: {w.creation_date}\n"
        if w.expiration_date:
            whois_text += f"Expiration Date: {w.expiration_date}\n"
        return whois_text
    except Exception as e:
        print(f"[WHOIS] RESPONSE={e}")
        return "WHOIS information could not be retrieved."


def get_analysis_report(analysis_url, headers, retries=4, delay=15):
    for attempt in range(retries):
        report_response = requests.get(analysis_url, headers=headers)
        if report_response.status_code == 200:
            report = report_response.json()
            if report['data']['attributes']['status'] == 'completed':
                return report
            else:
                print(f"[VIRUSTOTAL] ATTEMPT={attempt + 1}/{retries} STATUS=RETRY_IN_{delay}_SECONDS")
                time.sleep(delay)
        else:
            print(f"[VIRUSTOTAL] REASON=FAILED_TO_FETCH_RESULTS, STATUS= {report_response.status_code}")
            break
    return None


def submit_to_urlscan(link):
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": link, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code == 200:
        scan_uuid = response.json().get('uuid')
        return scan_uuid  # Return the uuid instead of the result URL
    else:
        print(f"[URLSCAN] RESPONSE={response.status_code}")
        return None


def get_urlscan_result(scan_uuid, retries=4, delay=15):
    result_url = f'https://urlscan.io/api/v1/result/{scan_uuid}/'  # Construct the result URL using the uuid

    for attempt in range(retries):
        time.sleep(delay)  # Wait before checking if the scan is ready
        response = requests.get(result_url)
        if response.status_code == 200:
            scan_data = response.json()
            return scan_data
        else:
            print(f"[URLSCAN] ATTEMPT={attempt + 1}/{retries}, REASON=FAILED_TO_FETCH_RESULTS, STATUS={response.status_code}")

    return None
