from fastapi import FastAPI, HTTPException
import requests
from zapv2 import ZAPv2

app = FastAPI()

# ZAP configuration
zap = ZAPv2(apikey='l5pkjbqiiup1hdg2bqk9cdlqkv',
            proxies={'http': 'http://localhost:8080', 'https': 'http://localhost:8080'})


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


@app.post("/scan")
async def initiate_scan():
    target_url = "https://www.voltsec-io.com/"

    # Perform ZAP active scan
    zap.spider.scan(target_url)
    zap.spider.wait_for_complete()
    zap.ascan.scan(target_url)
    zap.ascan.wait_for_complete()

    return {"message": "Scan initiated successfully"}


@app.get("/get-results")
async def get_scan_results():
    target_url = "https://www.voltsec-io.com/"

    # Retrieve ZAP scan results
    alerts = zap.core.alerts(baseurl=target_url)

    return {"zap_results": alerts}
