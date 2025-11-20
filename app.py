import streamlit as st
from dotenv import load_dotenv
import joblib
import tldextract
import numpy as np
import requests
import whois
import os
from datetime import datetime
from urllib.parse import urlparse
from base64 import urlsafe_b64encode
import virustotal_python
import diskcache as dc
import pandas as pd
from fastapi import FastAPI
from fastapi.responses import JSONResponse
# === CONFIGURATION ===
app = FastAPI(title="Phish Checker API")
load_dotenv(override=True)
cache = dc.Cache('./cache')
api_key = st.secrets["api_key"]

MODEL_FILE = 'phishing_model.pkl'
SCALER_FILE = 'scaler.pkl'
DATASET_FILE = "./modelTraining/final_data.csv"
LEGIT_DOMAINS_FILE = os.path.join("data", "realDomains.txt")

model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)
dataset = pd.read_csv(DATASET_FILE) if os.path.exists(DATASET_FILE) else pd.DataFrame()

def predict_url(url: str):
    try:
        features, domain = extract_features(url)
        scaled_features = scaler.transform([features])
        prediction = model.predict(scaled_features)[0]
        probabilities = model.predict_proba(scaled_features)[0]
        confidence = float(np.max(probabilities))
        is_legit = is_legit_domain(domain)
        vt_results = check_url_with_virustotal(url)

        if is_legit:
            verdict = "Legitimate"
            message = "Domain is known safe (realDomains list)."
            confidence = 1.0
        elif prediction == 1:
            verdict = "Phishing"
            message = "Model detected phishing characteristics."
        else:
            verdict = "Legitimate"
            message = "This URL appears legitimate."

        return {
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "confidence": confidence,
            "message": message,
            "virustotal": vt_results
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/predict")
def predict_endpoint(url: str):
    result = predict_url(url)
    return JSONResponse(content=result)

@app.post("/batch")
def batch_predict(urls: list[str]):
    if len(urls) > 10:
        return JSONResponse(content={"error": "Rate limit exceeded: max 10 URLs per batch"})
    results = [predict_url(u) for u in urls]
    return JSONResponse(content={"results": results})

HIGH_RISK_TLDS = [
    'xyz','top','club','site','online','rest','icu','work','click','fit','gq','tk','ml','cf','ga',
    'men','loan','download','stream','party','cam','win','bid','review','trade','accountant','science',
    'date','faith','racing','zip','cricket','host','press','space','pw','buzz','mom','bar','uno',
    'kim','country','support','webcam','rocks','info','biz','pro','link','pics','help','ooo',
    'asia','today','live','lol','surf','fun','run','cyou','monster','store'
]

# === HELPER FUNCTIONS ===
def load_legit_domains(filepath):
    try:
        with open(filepath, 'r') as f:
            return set(line.strip().lower().replace('https://', '').replace('http://', '') for line in f if line.strip())
    except Exception:
        return set()

LEGIT_DOMAINS = load_legit_domains(LEGIT_DOMAINS_FILE)

def is_legit_domain(domain):
    return domain.lower() in LEGIT_DOMAINS

def get_redirection_count(url):
    count = 0
    try:
        for _ in range(5):
            response = requests.head(url, allow_redirects=False, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            if 300 <= response.status_code < 400:
                url = response.headers.get('Location', url)
                count += 1
            else:
                break
    except Exception:
        pass
    return count

def is_using_cloudflare(url):
    try:
        response = requests.head(url, timeout=3)
        headers = response.headers
        return (
            headers.get('Server', '').lower().startswith('cloudflare') or
            'CF-RAY' in headers or
            'CF-Cache-Status' in headers
        )
    except Exception:
        return False

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date if hasattr(domain_info, "creation_date") else domain_info.get(
            "creation_date")
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            return (datetime.now() - creation_date).days
        return None
    except Exception:
        return None

def check_url_with_virustotal(url):
    key = api_key or os.getenv("VT_API_KEY")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    try:
        with virustotal_python.Virustotal(key) as vtotal:
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            data = report.json()
            if "data" in data:
                attrs = data["data"]["attributes"]
                stats = attrs["last_analysis_stats"]

                # Convert scan date (Unix timestamp) → readable
                ts = attrs.get("last_analysis_date")
                readable_date = None
                if ts:
                    readable_date = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")

                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_scans": sum(stats.values()),
                    "scan_date": ts,
                    "scan_date_readable": readable_date
                }
            return {"found": False, "message": "URL not found in VirusTotal database"}
    except Exception as e:
        return {"error": str(e)}


def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0].replace('www.', '')
    tld_extract = tldextract.extract(url)
    domain_name = f"{tld_extract.domain}.{tld_extract.suffix}"

    url_length = len(url)
    n_slash = url.count('/')
    n_questionmark = url.count('?')
    n_equal = url.count('=')
    n_at = url.count('@')
    n_and = url.count('&')
    n_exclamation = url.count('!')
    n_asterisk = url.count('*')
    n_hastag = url.count('#')
    n_percent = url.count('%')
    dots_per_length = url.count('.') / (url_length + 1)
    hyphens_per_length = url.count('-') / (url_length + 1)
    is_long_url = 1 if url_length > 200 else 0
    has_many_dots = 1 if url.count('.') > 4 else 0
    special_char_density = (
        n_slash + n_questionmark + n_equal + n_at + n_and +
        n_exclamation + n_asterisk + n_hastag + n_percent
    ) / (url_length + 1)
    has_ssl = 1 if url.startswith('https') else 0
    is_cloudflare_protected = is_using_cloudflare(url)
    suspicious_tld_risk = 1 if tld_extract.suffix in HIGH_RISK_TLDS else 0
    n_redirection = get_redirection_count(url)
    domain_age = get_domain_age(domain_name) or 0

    risk_score = (
        is_long_url * 2 +
        has_many_dots * 1.5 +
        special_char_density * 2 +
        n_redirection * 3 -
        has_ssl * 2 -
        is_cloudflare_protected * 5 -
        (domain_age / 365)
    )

    url_complexity = (
        url_length * 0.01 +
        n_slash * 0.5 +
        n_questionmark * 0.7 +
        n_equal * 0.7 +
        n_at * 2
    )

    features = [
        url_length, n_slash, n_questionmark, n_equal, n_at, n_and,
        n_exclamation, n_asterisk, n_hastag, n_percent,
        dots_per_length, hyphens_per_length, is_long_url, has_many_dots,
        has_ssl, is_cloudflare_protected, special_char_density,
        suspicious_tld_risk, n_redirection, risk_score, url_complexity
    ]
    return features, domain_name

# === LOAD MODEL AND DATASET ===
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)
dataset = pd.read_csv(DATASET_FILE) if os.path.exists(DATASET_FILE) else pd.DataFrame()

# === STREAMLIT APP ===
st.set_page_config(page_title="Phishing Detector", layout="wide")

# ---- Styling (dark-accent theme) ----
st.markdown(
    """
    <style>
      :root{
        --bg:#0f1724; --card:#0b1220; --muted:#9aa4b2; --accent:#3ddc97; --glass: rgba(255,255,255,0.03);
        --good:#1dd77a; --warn:#f59e0b; --bad:#ff6b6b;
      }
      html,body {background:var(--bg); color:#e6eef6; font-family:Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial; }
      .wrap {max-width:1100px;margin:28px auto;padding:20px;}
      h1 {margin:0;font-size:22px}
      .lead {color:var(--muted);margin-top:6px;font-size:13px}
      .card {background:var(--card);padding:18px;border-radius:12px;border:1px solid rgba(255,255,255,0.05)}
      .badge {padding:6px 10px;border-radius:8px;font-weight:700}
      .no-data {background:transparent;color:var(--muted);font-weight:700}
      footer {margin-top:18px;color:var(--muted);font-size:13px;text-align:center}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown("<div class='wrap'><h1>Phish Checker</h1><div class='lead'>Real‑time phishing URL detection</div></div>", unsafe_allow_html=True)

# TABS w/ credits
tab1, tab2, tab3, tab4, tab5 = st.tabs(["Single URL", "Batch URLs", "Model Info", "Dataset Info", "Credits"])

# SINGLE URL
with tab1:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.header("Single URL Checker")
    url_input = st.text_input("Enter a URL to analyze:")
    if st.button("Analyze URL") and url_input:
        with st.spinner("Analyzing URL..."):
            features, domain = extract_features(url_input)
            scaled_features = scaler.transform([features])
            prediction = model.predict(scaled_features)[0]
            probabilities = model.predict_proba(scaled_features)[0]
            confidence = float(np.max(probabilities))
            is_legit = is_legit_domain(domain)
            vt_results = check_url_with_virustotal(url_input)

            if is_legit:
                verdict = "Legitimate"
                message = "Domain is known safe (realDomains list)."
                confidence = 1.0
            elif prediction == 1:
                verdict = "Phishing"
                message = "Model detected phishing characteristics."
            else:
                verdict = "Legitimate"
                message = "This URL appears legitimate."

            st.subheader("Results")
            st.write(f"**Domain:** {domain}")
            st.write(f"**Verdict:** {verdict}")
            st.write(f"**Confidence:** {confidence:.2f}")
            st.write(f"**Message:** {message}")
            st.write("**VirusTotal Results:**")
            st.json(vt_results)
    st.markdown("</div>", unsafe_allow_html=True)

# BATCH URL
with tab2:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.header("Batch URL Scan (max 10)")
    batch_input = st.text_area("Enter multiple URLs (one per line):")
    if st.button("Analyze Batch URLs") and batch_input:
        urls = [line.strip() for line in batch_input.splitlines() if line.strip()]
        if len(urls) > 10:
            st.error("Rate limit exceeded: max 10 URLs per batch")
        else:
            results = []
            with st.spinner("Analyzing batch URLs..."):
                for url in urls:
                    features, domain = extract_features(url)
                    scaled_features = scaler.transform([features])
                    prediction = model.predict(scaled_features)[0]
                    probabilities = model.predict_proba(scaled_features)[0]
                    confidence = float(np.max(probabilities))
                    is_legit = is_legit_domain(domain)
                    vt_results = check_url_with_virustotal(url)

                    if is_legit:
                        verdict = "Legitimate"
                        message = "Domain is known safe (realDomains list)."
                        confidence = 1.0
                    elif prediction == 1:
                        verdict = "Phishing"
                        message = "Model detected phishing characteristics."
                    else:
                        verdict = "Legitimate"
                        message = "This URL appears legitimate."

                    results.append({
                        "URL": url,
                        "Domain": domain,
                        "Verdict": verdict,
                        "Confidence": confidence,
                        "Message": message,
                        "VirusTotal": vt_results
                    })
            st.dataframe(pd.DataFrame(results))
    st.markdown("</div>", unsafe_allow_html=True)

# MODEL INFO
with tab3:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.header("Model Information")
    st.write(f"Model file: {MODEL_FILE}")
    st.write(f"Scaler file: {SCALER_FILE}")
    st.write(f"Algorithm: {type(model).__name__}")
    st.write(f"Number of features: {model.n_features_in_}")
    st.write(f"Classes: {model.classes_.tolist()}")
    st.markdown("</div>", unsafe_allow_html=True)

# DATASET INFO
with tab4:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.header("Dataset Information")
    if dataset.empty:
        st.warning("Dataset not found or empty")
    else:
        st.write(f"Dataset file: {DATASET_FILE}")
        st.write(f"Number of samples: {len(dataset)}")
        st.write(f"Number of features: {dataset.shape[1]}")
        st.write(f"Columns: {dataset.columns.tolist()}")
        st.dataframe(dataset.head())
    st.markdown("</div>", unsafe_allow_html=True)

# CREDITS
with tab5:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.header("Credits")
    st.markdown("""
**Phish Checker — A Machine Learning–Powered URL Security Analyzer**

**Contributors**
- **J.E. Formilles** – Model Training, Backend  
- **J.C. Ronquillo** – FrontEnd, BackEnd, Deployment
- **A.R. Advincula** – FrontEnd, BackEnd, Deployment 

**Technologies & Tools**
- **Machine Learning:** scikit-learn, joblib  
- **Data Processing:** pandas, NumPy  
- **Security & Threat Intelligence:** VirusTotal API, python-whois, tldextract  
- **Web Platform:** Streamlit  
- **Caching:** diskcache  
- **Backend API (local use):** FastAPI

**Project Purpose**
Phish Checker is designed to help users identify suspicious or phishing URLs  
using ML-based predictions, domain intelligence, and real-time VirusTotal lookups.

""")
    st.markdown("</div>", unsafe_allow_html=True)

# Footer
st.markdown("<footer>No personal data is stored beyond submitted URLs. "
            "Powered by Streamlit</footer>", unsafe_allow_html=True)
