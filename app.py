import streamlit as st
from dotenv import load_dotenv
import joblib
import tldextract
import numpy as np
import requests
import whois
import ipaddress
import math
import os
from datetime import datetime
from urllib.parse import urlparse
from base64 import urlsafe_b64encode
import virustotal_python
import diskcache as dc
import pandas as pd

# === CONFIGURATION ===
load_dotenv(override=True)
cache = dc.Cache('./cache')
api_key = os.getenv("VT_API_KEY")

MODEL_FILE = 'phishing_model.pkl'
SCALER_FILE = 'scaler.pkl'
DATASET_FILE = 'final_data.csv'
LEGIT_DOMAINS_FILE = 'realDomains.txt'

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
            headers.get('Server', '').startswith('cloudflare') or
            'CF-RAY' in headers or
            'CF-Cache-Status' in headers
        )
    except:
        return False

def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except:
        return None

def is_ip_address(url):
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        ipaddress.ip_address(netloc)
        return True
    except:
        return False

def check_url_with_virustotal(url):
    key = api_key or os.getenv("VT_API_KEY")
    if not key:
        return {"error": "VirusTotal API key not configured"}
    with virustotal_python.Virustotal(key) as vtotal:
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        try:
            report = vtotal.request(f"urls/{url_id}")
            data = report.json()
            if "data" in data:
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_scans": sum(stats.values()),
                    "scan_date": data["data"]["attributes"].get("last_analysis_date")
                }
            else:
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

# === LOAD MODEL AND SCALER ===
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

# === STREAMLIT UI ===
st.title("Phishing URL Detection")

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

        st.write("### Results")
        st.write(f"**URL:** {url_input}")
        st.write(f"**Domain:** {domain}")
        st.write(f"**Verdict:** {verdict}")
        st.write(f"**Confidence:** {confidence:.2f}")
        st.write(f"**Message:** {message}")
        st.write("**VirusTotal Results:**")
        st.json(vt_results)


