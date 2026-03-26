import streamlit as st
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

st.set_page_config(page_title="ELITE RECON", layout="wide")

# ===============================
# CORE ENGINE
# ===============================

def fetch(url):
    try:
        r = requests.get(url, timeout=10)
        return r.text, r.headers, r.status_code
    except:
        return "", {}, 0

def extract_js(html, base):
    soup = BeautifulSoup(html, "html.parser")
    js_files = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            js_files.append(urljoin(base, src))
    return js_files

def extract_endpoints(js_content):
    pattern = r"(https?://[^\s\"']+|/[\w\-\/?=&]+)"
    return re.findall(pattern, js_content)

def find_params(urls):
    params = []
    for u in urls:
        if "?" in u:
            params.append(u.split("?")[1])
    return params

def detect_vulns(params):
    findings = []

    for p in params:
        if "url=" in p or "redirect=" in p:
            findings.append(("Potential SSRF/Open Redirect", p))

        if "id=" in p or "user=" in p:
            findings.append(("Potential IDOR", p))

    return findings

def risk_score(findings):
    score = len(findings) * 20
    return min(score, 100)

# ===============================
# UI
# ===============================

st.title("🔥 ELITE RECON FRAMEWORK")
st.caption("All-in-One Bug Bounty Dashboard")

target = st.text_input("🎯 Target URL", "https://example.com")

if st.button("🚀 START FULL SCAN"):

    st.subheader("📡 Step 1: Fetching Target")
    html, headers, status = fetch(target)

    if status == 0:
        st.error("Target unreachable")
        st.stop()

    st.success(f"Status Code: {status}")

    st.subheader("🧠 Step 2: Headers")
    st.json(dict(headers))

    st.subheader("📜 Step 3: Extract JS Files")
    js_files = extract_js(html, target)

    for js in js_files:
        st.write(js)

    all_endpoints = []

    st.subheader("🔍 Step 4: JS Analysis")
    for js in js_files:
        js_content, _, _ = fetch(js)
        endpoints = extract_endpoints(js_content)
        all_endpoints.extend(endpoints)

    st.write(f"Found {len(all_endpoints)} endpoints")

    st.subheader("🧩 Step 5: Parameter Discovery")
    params = find_params(all_endpoints)

    for p in params:
        st.code(p)

    st.subheader("💀 Step 6: Vulnerability Detection")
    vulns = detect_vulns(params)

    if vulns:
        for v in vulns:
            st.error(f"{v[0]} → {v[1]}")
    else:
        st.success("No obvious vulns detected")

    st.subheader("📊 Step 7: Risk Score")
    score = risk_score(vulns)

    st.progress(score)

    if score > 70:
        st.error("🔥 HIGH RISK TARGET")
    elif score > 40:
        st.warning("⚠️ MEDIUM RISK")
    else:
        st.success("✅ LOW RISK")

    st.subheader("📦 Summary")
    st.write({
        "JS Files": len(js_files),
        "Endpoints": len(all_endpoints),
        "Params": len(params),
        "Findings": len(vulns),
        "Risk Score": score
    })
