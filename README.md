# Sentinel AI — Single Agent Project

Streamlit dashboard: Random Forest (synthetic demo data) + rule-guided agent + live
threat intelligence from **AbuseIPDB** and **VirusTotal**. Blocking is simulated only.

## Files
- `app.py` – main app (set this as the Main file path on Streamlit Cloud)
- `threat_intel.py` – AbuseIPDB / VirusTotal clients (keys from Secrets, errors handled)
- `requirements.txt` – dependencies
- `.streamlit/secrets.toml.example` – template for your keys (never commit the real file)

## API keys
- AbuseIPDB: https://www.abuseipdb.com/account/api  (free key)
- VirusTotal: https://www.virustotal.com/gui/my-apikey  (free key)

Keys are optional: without them the dashboard still runs and shows a friendly notice.

## Run locally (Windows)
```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .streamlit\secrets.toml.example .streamlit\secrets.toml   (then edit it with your keys)
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Create a GitHub repo and upload these files (`.gitignore` keeps secrets.toml out).
2. Go to https://share.streamlit.io → **Create app** → pick the repo, branch `main`,
   **Main file path: `app.py`**.
3. Open **Advanced settings → Secrets** and paste:
```
ABUSEIPDB_API_KEY = "your-key"
VIRUSTOTAL_API_KEY = "your-key"
```
4. Click **Deploy**. Your URL will look like `https://<your-app-name>.streamlit.app`.
   Secrets can be changed later in App → Settings → Secrets.
