# """PhishGuard dashboard: URL, QR, screenshot, and dataset workflows."""

import os
import sys
import tempfile
import hmac
from html import escape
from datetime import datetime
from io import BytesIO

import cv2
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image
from dotenv import load_dotenv

load_dotenv()
TRAINING_ADMIN_PASSWORD = os.getenv("PHISHGUARD_ADMIN_PASSWORD", "").strip()


SRC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from ai_explainer import AI_ENABLED, explain_qr, explain_url, explain_visual
from drift_verifier import verify_url
from model_training import inspect_dataset, train_uploaded_dataset
from predict_url import predict_url, reload_model
from risk_engine import calculate_risk
from url_safety import normalize_url
from user_auth import (
    authenticate_account,
    create_account,
    delete_scan_history,
    get_scan_history,
    initialize_database,
    save_scan,
)
from visual_detector import detect_visual_phishing


st.set_page_config(
    page_title="PhishGuard | Phishing Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    :root { color-scheme: light; }
    .stApp { background: linear-gradient(135deg,#f4f8ff 0%,#edf4ff 48%,#f8faff 100%); color:#10172b; }
    [data-testid="stHeader"] { background:transparent; }
    [data-testid="stMain"] .block-container { max-width:1580px; padding:1.35rem 1.7rem 3rem; }
    [data-testid="stSidebar"] { background:linear-gradient(180deg,#071225 0%,#0d1b35 100%); border-right:1px solid #1e3154; }
    [data-testid="stSidebar"] * { color:#e8efff; }
    .brand-lockup { display:flex; align-items:center; gap:.65rem; padding:1rem .2rem .1rem; white-space:nowrap; }
    .brand-lockup .brand-shield { font-size:43px !important; line-height:1; }
    .brand-lockup .brand-name { font-size:36px !important; line-height:1.1; font-weight:850; letter-spacing:-.045em; }
   
    .brand-lockup .brand-name span { color:#35b9ff; }
    .brand-tagline { margin:.34rem 0 1.05rem 3rem; color:#b6c4dc; font-size:.8rem; white-space:nowrap; }

    [data-testid="stSidebar"] [data-testid="stRadio"] label { border-radius:11px; padding:.55rem .72rem; margin:.14rem 0; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { background:#172c50; }
    [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) { background:linear-gradient(100deg,#183b75,#142747); }
    [data-testid="stSidebar"] [data-testid="stRadio"] label p { color:#d8e4ff; font-weight:600; }
    [data-testid="stSidebar"] div.stButton > button { width:100%; background:#1d4ed8 !important; color:#fff !important; border:1px solid #60a5fa !important; border-radius:10px !important; font-weight:700 !important; }
    [data-testid="stSidebar"] div.stButton > button:hover { background:#2563eb !important; border-color:#93c5fd !important; color:#fff !important; }
    [data-testid="stSidebar"] div.stButton > button * { color:#fff !important; }
    div[data-testid="stRadio"] input[type="radio"] { accent-color:#2874ed !important; }
    div[data-testid="stFormSubmitButton"] > button[kind="primary"] { background:linear-gradient(90deg,#1876ef,#2860ec) !important; color:#fff !important; border:0 !important; border-radius:10px !important; font-weight:700 !important; }
    div[data-testid="stFormSubmitButton"] > button[kind="primary"]:hover { background:#1d4ed8 !important; color:#fff !important; }
    
    h1,h2,h3 { color:#10172b !important; letter-spacing:-.025em; }
    .hero { display:flex; align-items:center; justify-content:space-between; gap:1rem; min-height:185px; padding:1.45rem 1.8rem; margin:.1rem 0 1rem; border:1px solid #d7e7ff; border-radius:18px; background:linear-gradient(105deg,#ffffff 0%,#e7f2ff 59%,#dce9ff 100%); box-shadow:0 10px 28px rgba(35,79,143,.09); overflow:hidden; }
    .hero h1 { font-size:clamp(1.65rem,2.5vw,2.55rem); margin:0 0 .35rem; line-height:1.14; }
    .hero h1 span { background:linear-gradient(90deg,#2874ed,#7044ec); -webkit-background-clip:text; color:transparent; }
    .hero p { max-width:670px; color:#4b5875; margin:.3rem 0 .85rem; }
    .hero-pills { display:flex; gap:.65rem; flex-wrap:wrap; color:#384665; font-size:.88rem; }
    .hero-pills span { background:#fff9; border:1px solid #d8e5ff; border-radius:99px; padding:.35rem .65rem; }
    .hero-art { min-width:205px; width:260px; height:150px; display:flex; align-items:center; justify-content:center; }
    .screen-art { width:200px; height:126px; border:5px solid #173963; border-radius:13px; background:linear-gradient(150deg,#0c2650,#2558ad); box-shadow:0 12px 20px #214e9870; display:flex; align-items:center; justify-content:center; position:relative; }
    .screen-art:before { content:'🛡️'; font-size:4.2rem; filter:drop-shadow(0 4px 6px #0008); }
    .screen-art:after { content:'🔒'; position:absolute; right:9px; bottom:7px; font-size:1.5rem; }
    [data-testid="stVerticalBlockBorderWrapper"] { background:#fff; border:1px solid #e1e9f5; border-radius:16px; box-shadow:0 5px 18px rgba(18,44,84,.045); }
    .card-heading { display:flex; align-items:center; gap:.72rem; margin:.05rem 0 .1rem; }
    .card-icon { width:46px; height:46px; flex:0 0 46px; display:grid; place-items:center; border-radius:50%; background:#e7f2ff; color:#1769e8; font-size:1.4rem; }
    .card-icon.green { background:#e5faef; color:#078a52; }
    .card-icon.purple { background:#f0eaff; color:#6538e9; }
    .card-heading h3 { margin:0; font-size:1.03rem; }
    .card-heading small { display:block; color:#64708c; margin-top:.14rem; }
    .result-panel { padding:1.2rem; border-radius:16px; background:#fff; border:1px solid #e1e9f5; box-shadow:0 5px 18px rgba(18,44,84,.045); }
    .verdict { border-radius:14px; padding:1.05rem 1.15rem; min-height:140px; }
    .verdict.danger { background:linear-gradient(120deg,#fff0f0,#fff8f8); border:1px solid #ffd5d5; }
    .verdict.warning { background:linear-gradient(120deg,#fff8e8,#fffcf5); border:1px solid #ffe7b6; }
    .verdict.safe { background:linear-gradient(120deg,#edfbf3,#f8fffb); border:1px solid #ccefdc; }
    .verdict h3 { margin:0 0 .25rem; font-size:1.13rem; }
    .verdict p { color:#4e5870; margin:.2rem 0; }
    .verdict h3, .verdict p { color:#10172b !important; }
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"],
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"] * { color:#10172b !important; }
    .gauge { width:142px; height:142px; border-radius:50%; display:grid; place-items:center; margin:.35rem auto; background:conic-gradient(var(--gauge-color) calc(var(--score) * 1%),#e8edf5 0); }
    .gauge-inner { width:115px; height:115px; border-radius:50%; background:#fff; display:flex; flex-direction:column; align-items:center; justify-content:center; }
    .gauge-inner strong { color:#111a2e; font-size:1.65rem; }
    .gauge-inner span { color:#69758d; font-size:.8rem; }
    .finding { padding:.48rem .1rem; border-bottom:1px solid #edf0f5; color:#38445c; font-size:.9rem; }
    .finding:last-child { border-bottom:0; }
    .example-box { padding:.65rem .75rem; margin-top:.6rem; border-radius:10px; background:#eef6ff; color:#53627e; font-size:.8rem; }
    .example-box code { color:#345181; background:transparent; }
    .muted { color:#69758d; }
    div.stButton > button[kind="primary"] { border:0; border-radius:10px; background:linear-gradient(90deg,#1876ef,#2860ec); color:#fff; font-weight:700; }
    .st-key-home_qr button, .st-key-qr_submit button { background:linear-gradient(90deg,#079b69,#159e72) !important; }
    .st-key-home_screen button, .st-key-screen_submit button { background:linear-gradient(90deg,#6844ed,#7138e6) !important; }
    [data-testid="stFileUploader"] { border-radius:12px; }
    .stDataFrame { border-radius:12px; overflow:hidden; }
    div[data-testid="stTextInput"] input { min-height:48px; border:1px solid #8292ad !important; border-radius:10px !important; background:#fff !important; color:#10172b !important; }
    div[data-testid="stTextInput"] input::placeholder { color:#66748b !important; opacity:1; }
    @media(max-width:900px) { .hero-art { display:none; } [data-testid="stMain"] .block-container { padding:.8rem .8rem 2rem; } }
    </style>
    """,
    unsafe_allow_html=True,
)


initialize_database()
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "scan_history" not in st.session_state:
    st.session_state.scan_history = []
if "latest_scan" not in st.session_state:
    st.session_state.latest_scan = None


def add_scan(item):
    item["timestamp"] = datetime.now().strftime("%d %b %Y, %I:%M %p")
    st.session_state.latest_scan = item
    user = st.session_state.current_user
    save_scan(user["id"], item)
    st.session_state.scan_history = get_scan_history(user["id"], limit=200)


def clear_current_user_history():
    user = st.session_state.current_user
    delete_scan_history(user["id"])
    st.session_state.scan_history = []
    st.session_state.latest_scan = None


def classify_label(result):
    if result.get("type") == "Screenshot":
        return "Phishing signal" if result.get("risk") == "High" else "Lower visual risk"
    # Keep the headline aligned with the combined model + rule-based risk.
    # A legitimate model label must not hide meaningful medium/high rule risk.
    if result.get("risk") == "High":
        return "High risk — review carefully"
    if result.get("risk") == "Medium":
        return "Suspicious — use caution"
    return {-1: "Phishing signal", 0: "Inconclusive", 1: "No phishing signal"}.get(result.get("prediction"), "Unknown")


def scan_destination(raw_url, source="URL"):
    url = normalize_url(raw_url)
    prediction, confidence = predict_url(url)
    drift = verify_url(url)
    score, risk, reasons = calculate_risk(url, prediction, drift, confidence)
    explanation = None
    if AI_ENABLED:
        try:
            function = explain_qr if source == "QR Code" else explain_url
            explanation = function(url, prediction, confidence, score, risk, reasons, drift)
        except Exception:
            explanation = None
    add_scan({
        "type": source,
        "input": url,
        "prediction": prediction,
        "confidence": confidence,
        "score": score,
        "risk": risk,
        "reasons": reasons,
        "drift": drift,
        "explanation": explanation,
    })


def scan_qr_image(upload):
    if upload.size > 5 * 1024 * 1024:
        raise ValueError("QR images must be 5 MB or smaller.")
    image = Image.open(BytesIO(upload.getvalue()))
    if image.width * image.height > 30_000_000:
        raise ValueError("This image is too large to process safely.")
    image = image.convert("RGB")
    image_array = cv2.cvtColor(np.asarray(image), cv2.COLOR_RGB2BGR)
    raw, points, _ = cv2.QRCodeDetector().detectAndDecode(image_array)
    if not raw:
        raise ValueError("No readable QR code was found in this image.")
    scan_destination(raw, "QR Code")


def scan_screenshot(upload):
    if upload.size > 5 * 1024 * 1024:
        raise ValueError("Screenshot images must be 5 MB or smaller.")
    image = Image.open(BytesIO(upload.getvalue()))
    if image.width * image.height > 30_000_000:
        raise ValueError("This image is too large to process safely.")
    image = image.convert("RGB")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp_file:
            temp_path = temp_file.name
        image.save(temp_path, format="PNG")
        visual = detect_visual_phishing(temp_path)
        explanation = None
        if AI_ENABLED:
            try:
                explanation = explain_visual(visual["result"], visual["confidence"], visual["reasons"])
            except Exception:
                explanation = None
        add_scan({
            "type": "Screenshot",
            "input": upload.name,
            "prediction": None,
            "confidence": visual["confidence"],
            "score": visual["score"],
            "risk": visual["risk"],
            "reasons": visual["reasons"],
            "visual_result": visual["result"],
            "explanation": explanation,
        })
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def render_card_heading(icon, title, subtitle, color=""):
    st.markdown(
        f'<div class="card-heading"><div class="card-icon {color}">{icon}</div>'
        f'<div><h3>{title}</h3><small>{subtitle}</small></div></div>',
        unsafe_allow_html=True,
    )


def render_url_card(prefix="home"):
    with st.form(f"{prefix}_url_form"):
        url = st.text_input("Website URL", placeholder="https://example.com", key=f"{prefix}_url")
        submitted = st.form_submit_button("⌕  Analyze URL", width="stretch", type="primary")
    if submitted:
        if not url.strip():
            st.warning("Enter a URL to scan.")
        else:
            with st.spinner("Analyzing the URL and destination signals…"):
                try:
                    scan_destination(url, "URL")
                    st.success("URL scan complete. See the latest result below.")
                except Exception as error:
                    st.error(f"Could not scan that URL: {error}")
    st.markdown(
        '<div class="example-box"><b>Examples</b><br>🔗 https://www.google.com<br>'
        '🔗 https://www.paypal.com<br>🔗 http://example.net/login</div>',
        unsafe_allow_html=True,
    )


def render_qr_card(prefix="home"):
    upload = st.file_uploader("Upload QR image", type=["png", "jpg", "jpeg", "webp", "bmp"], key=f"{prefix}_qr_upload")
    if upload is not None:
        st.image(upload, width="stretch")
    if st.button("▦  Analyze QR Code", width="stretch", type="primary", key=f"{prefix}_qr"):
        if upload is None:
            st.warning("Choose a QR image first.")
        else:
            with st.spinner("Reading the QR code and checking its destination…"):
                try:
                    scan_qr_image(upload)
                    st.success("QR scan complete. See the latest result below.")
                except Exception as error:
                    st.error(f"Could not scan this QR image: {error}")


def render_screenshot_card(prefix="home"):
    upload = st.file_uploader("Upload website screenshot", type=["png", "jpg", "jpeg", "webp", "bmp"], key=f"{prefix}_screen_upload")
    if upload is not None:
        st.image(upload, width="stretch")
    if st.button("▧  Analyze Screenshot", width="stretch", type="primary", key=f"{prefix}_screen"):
        if upload is None:
            st.warning("Choose a screenshot first.")
        else:
            with st.spinner("Analyzing the screenshot…"):
                try:
                    scan_screenshot(upload)
                    st.success("Screenshot scan complete. See the latest result below.")
                except Exception as error:
                    st.error(f"Could not analyze this screenshot: {error}")


def local_explanation(result):
    label = classify_label(result)
    reasons = result.get("reasons") or ["No additional indicators were supplied by the scanner."]
    level = result.get("risk", "Unknown").lower()
    if label == "Inconclusive":
        opening = "The available signals are inconclusive, so treat this destination carefully."
    else:
        opening = f"The scan indicates {level} risk based on the available checks."
    evidence = "; ".join(reasons[:2])
    recommendation = "Open unexpected links cautiously, and do not enter passwords or payment details unless you verify the destination independently."
    return f"{opening}\n\n{evidence}\n\n💡 Recommendation: {recommendation}"


def render_latest_result():
    result = st.session_state.latest_scan
    st.markdown("### ◷  Latest Scan Result")
    if result is None:
        st.info("Your latest URL, QR, or screenshot result will appear here.")
        return

    label = classify_label(result)
    score = max(0, min(100, int(result.get("score", 0))))
    safe_input = escape(str(result.get("input", "")))
    tone = "danger" if result.get("risk") == "High" else "warning" if result.get("risk") == "Medium" or label == "Inconclusive" else "safe"
    color = "#ef3340" if tone == "danger" else "#f0a321" if tone == "warning" else "#12a56b"
    left, right = st.columns([1.15, 2.85], gap="large")
    with left:
        st.markdown(
            f'<div class="gauge" style="--score:{score};--gauge-color:{color}"><div class="gauge-inner">'
            f'<strong>{score}%</strong><span>Risk Score</span></div></div>',
            unsafe_allow_html=True,
        )
        st.caption(f"{result['type']} scan · {result['timestamp']}")
        st.caption(f"Model confidence: {result.get('confidence', 'N/A')}%")
    with right:
        summary = "The model found phishing signals. Verify the domain before continuing." if label == "Phishing signal" else (
            "The combined checks found warning signs. This is not proof of phishing, but verify the domain before continuing." if label == "Suspicious — use caution" else
            "High risk signals were found. Do not enter sensitive information unless you independently verify the destination." if label == "High risk — review carefully" else
            "The available evidence is mixed; the model cannot make a stable verdict." if label == "Inconclusive" else
            "No strong phishing signal was found by the available checks. This does not guarantee safety."
        )
        st.markdown(
            f'<div class="verdict {tone}"><h3>{"⚠️ " if tone == "danger" else "🔎 " if tone == "warning" else "✓ "}{label}</h3>'
            f'<p>{summary}</p><p><b>Scanned:</b> {safe_input}</p></div>',
            unsafe_allow_html=True,
        )
        explanation = result.get("explanation") or local_explanation(result)
        st.markdown("**Scan explanation**")
        st.write(explanation)


def render_findings():
    result = st.session_state.latest_scan
    st.markdown("### 💡  Key Findings")
    if result is None:
        st.caption("Run a scan to see its strongest signals.")
        return
    items = result.get("reasons") or ["No additional indicators detected."]
    for index, reason in enumerate(items[:7]):
        icon = "🟠" if index == 0 and result.get("risk") in {"High", "Medium"} else "🔹"
        st.markdown(f'<div class="finding">{icon} &nbsp; {reason}</div>', unsafe_allow_html=True)
    if result.get("drift"):
        status = result["drift"].get("status", "Unknown")
        st.markdown(f'<div class="finding">🌐 &nbsp; Active link: {status}</div>', unsafe_allow_html=True)


def render_history():
    st.markdown("### ◷  Scan History")
    history = get_scan_history(st.session_state.current_user["id"], limit=200)
    st.session_state.scan_history = history
    if not history:
        st.caption("Scans from this app session will be listed here.")
        return
    rows = []
    for index, item in enumerate(history, start=1):
        rows.append({
            "#": index,
            "Date & Time": item["timestamp"],
            "Type": item["type"],
            "Input": item["input"],
            "Result": classify_label(item),
            "Risk Score": f"{item.get('score', 0)}%",
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def render_latest_sections():
    result_col, finding_col = st.columns([1.8, 1], gap="small")
    with result_col:
        with st.container(border=True):
            render_latest_result()
    with finding_col:
        with st.container(border=True):
            render_findings()
    with st.container(border=True):
        history_col, button_col = st.columns([5, 1])
        with history_col:
            render_history()
        with button_col:
            if st.session_state.scan_history:
                if st.button("⌫ Clear History", key="clear_history", width="stretch"):
                    clear_current_user_history()
                    st.rerun()


def render_training_page():
    st.title("Upload URL Dataset")
    if not TRAINING_ADMIN_PASSWORD:
        st.warning(
            "Dataset training is locked. Only the project owner should enable it by setting "
            "PHISHGUARD_ADMIN_PASSWORD in the local .env file. Scanning remains available."
        )
        return

    if not st.session_state.get("training_admin_authenticated", False):
        st.write("Model training is restricted to the project owner.")
        entered_password = st.text_input(
            "Enter the owner password",
            type="password",
            placeholder="Type the password from your project .env file",
            help="This must match PHISHGUARD_ADMIN_PASSWORD in the project's .env file.",
            key="training_admin_password",
        )
        if st.button("Unlock dataset training", type="primary", key="unlock_training"):
            if hmac.compare_digest(entered_password, TRAINING_ADMIN_PASSWORD):
                st.session_state.training_admin_authenticated = True
                st.rerun()
            else:
                st.error("That password is not correct. The active model has not been changed.")
        return

    st.write("Train and activate a model from your labeled 30-feature URL CSV.")
    if st.button("Lock training", key="lock_training"):
        st.session_state.training_admin_authenticated = False
        st.rerun()
    st.info("The new model excludes HTTPS so a missing HTTPS signal alone cannot cause a phishing prediction. Mixed model scores are returned as inconclusive.")
    upload = st.file_uploader("Upload labeled feature CSV", type=["csv"], key="training_upload")
    if upload is None:
        return
    try:
        raw = upload.getvalue()
        if len(raw) > 25 * 1024 * 1024:
            raise ValueError("CSV uploads are limited to 25 MB.")
        frame = pd.read_csv(BytesIO(raw), low_memory=False)
        if len(frame) > 500_000:
            raise ValueError("CSV uploads are limited to 500,000 rows.")
        target, _ = inspect_dataset(frame)
        label_values = sorted(frame[target].dropna().astype(str).str.strip().unique())
        if len(label_values) != 2:
            st.error("The target column must contain exactly two labels.")
            return
        st.write(f"Detected {len(frame):,} rows and label column **{target}**.")
        phishing_value = st.selectbox("Which value means phishing?", label_values, key="phishing_label")
        st.dataframe(frame.head(8), width="stretch")
        if st.button("Train and activate model", type="primary", key="train_model"):
            with st.spinner("Evaluating the dataset and training the model…"):
                bundle, _ = train_uploaded_dataset(frame, target, phishing_value)
                reload_model()
            metrics = bundle["metrics"]
            st.success(f"{bundle['model_name']} is now active. The bundled classifier is preserved.")
            cols = st.columns(4)
            cols[0].metric("Test rows", metrics["test_rows"])
            cols[1].metric("Test coverage", f"{metrics['coverage_percent']}%")
            cols[2].metric("Phishing precision", f"{metrics['phishing_precision_percent']}%")
            cols[3].metric("Phishing recall", f"{metrics['phishing_recall_percent']}%")
            st.write(
                f"Held-out accuracy **{metrics['accuracy_percent']}%** · "
                f"Balanced accuracy **{metrics['balanced_accuracy_percent']}%** · "
                f"Phishing F1 **{metrics['phishing_f1_percent']}%** · "
                f"Validation false-positive rate **{metrics['validation_false_positive_rate_percent']}%**"
            )
            st.caption("Inconclusive predictions are excluded from the binary metrics and reflected in coverage.")
            st.write("Confusion matrix (phishing, legitimate):")
            st.code(str(metrics["confusion_matrix_phishing_then_legitimate"]))
    except Exception as error:
        st.error(f"Could not use this dataset: {error}")


def render_login_page():
    st.markdown(
        '<section class="hero"><div><h1>Welcome to <span>PhishGuard</span></h1>'
        '<p>Sign in to keep your scan history private to your account.</p></div>'
        '<div class="hero-art"><div class="screen-art"></div></div></section>',
        unsafe_allow_html=True,
    )
    left, form_col, right = st.columns([1, 1.2, 1])
    with form_col:
        with st.container(border=True):
            mode = st.radio("Account", ["Log in", "Create account"], horizontal=True, key="account_mode")
            if mode == "Log in":
                with st.form("login_form"):
                    username = st.text_input("Username", key="login_username")
                    password = st.text_input("Password", type="password", key="login_password")
                    submitted = st.form_submit_button("Log in", type="primary", width="stretch")
                if submitted:
                    user = authenticate_account(username, password)
                    if user is None:
                        st.error("Username or password is incorrect.")
                    else:
                        st.session_state.current_user = user
                        history = get_scan_history(user["id"], limit=200)
                        st.session_state.scan_history = history
                        st.session_state.latest_scan = history[0] if history else None
                        st.session_state.pop("login_password", None)
                        st.session_state.pop("training_admin_authenticated", None)
                        st.rerun()
            else:
                with st.form("create_account_form"):
                    username = st.text_input("Choose a username", key="new_username")
                    password = st.text_input("Choose a password (10+ characters)", type="password", key="new_password")
                    confirmation = st.text_input("Confirm password", type="password", key="confirm_password")
                    submitted = st.form_submit_button("Create account", type="primary", width="stretch")
                if submitted:
                    if password != confirmation:
                        st.error("The passwords do not match.")
                    else:
                        try:
                            user = create_account(username, password)
                            st.session_state.current_user = user
                            st.session_state.scan_history = []
                            st.session_state.latest_scan = None
                            for key in ("new_password", "confirm_password"):
                                st.session_state.pop(key, None)
                            st.success("Account created. You are now signed in.")
                            st.rerun()
                        except ValueError as error:
                            st.error(str(error))
            st.caption("Your account and scan history are stored in this app's local database.")


if st.session_state.current_user is None:
    render_login_page()
    st.stop()


with st.sidebar:
    st.markdown(
        '<div style="padding:.8rem .25rem 1.15rem"><div style="font-size:1.45rem;font-weight:800;letter-spacing:-.04em">🛡️ Phish<span style="color:#35b9ff">Guard</span></div>'
        '<div style="color:#b6c4dc;font-size:.78rem;margin-left:2.55rem">Detect. Protect. Stay Safe.</div></div>',
        unsafe_allow_html=True,
    )
    page = st.radio(
        "Navigation",
        ["⌂  Home", "⌕  URL Scanner", "▦  QR Scanner", "▧  Website Screenshot", "◷  Scan History", "ⓘ  Upload Dataset", "ⓘ  About"],
        label_visibility="collapsed",
        key="navigation",
    )
    st.caption(f"Signed in as **{st.session_state.current_user['username']}**")
    if st.button("Log out", key="logout", width="stretch"):
        for key in ("current_user", "scan_history", "latest_scan", "training_admin_authenticated", "training_admin_password"):
            st.session_state.pop(key, None)
        st.rerun()
    


if page.startswith("⌂"):
    st.markdown(
        '<section class="hero"><div><h1>Stay Safe from <span>Phishing Threats</span></h1>'
        '<p>Scan URLs, QR codes, or website screenshots to check for phishing and suspicious websites.</p>'
        '<div class="hero-pills"><span>⚙️ AI powered detection</span><span>♧ Multiple input types</span><span>▤ Clear explanations</span></div></div>'
        '<div class="hero-art"><div class="screen-art"></div></div></section>',
        unsafe_allow_html=True,
    )
    url_col, qr_col, screen_col = st.columns(3, gap="small")
    with url_col:
        with st.container(border=True):
            render_card_heading("🔗", "URL Scanner", "Check a website for suspicious signs.")
            render_url_card("home")
    with qr_col:
        with st.container(border=True):
            render_card_heading("▦", "QR Code Scanner", "Decode and analyze the destination.", "green")
            render_qr_card("home")
    with screen_col:
        with st.container(border=True):
            render_card_heading("▧", "Website Screenshot", "Check a screenshot for visual phishing.", "purple")
            render_screenshot_card("home")
    render_latest_sections()

elif page.startswith("⌕"):
    st.title("URL Scanner")
    st.write("Enter a URL to inspect its structure, model signals, and active response.")
    with st.container(border=True):
        render_card_heading("🔗", "Analyze a website", "HTTP sites are assessed on their evidence; HTTP alone is not a phishing verdict.")
        render_url_card("urlpage")
    render_latest_sections()

elif page.startswith("▦"):
    st.title("QR Code Scanner")
    st.write("Upload an image to decode and analyze its website destination.")
    with st.container(border=True):
        render_card_heading("▦", "Scan QR image", "PNG, JPG, JPEG, WebP, or BMP · maximum 5 MB", "green")
        render_qr_card("qrpage")
    render_latest_sections()

elif page.startswith("▧"):
    st.title("Website Screenshot Analyzer")
    st.write("Use the included visual classifier as an additional research signal, not a final verdict.")
    with st.container(border=True):
        render_card_heading("▧", "Analyze screenshot", "PNG, JPG, JPEG, WebP, or BMP · maximum 5 MB", "purple")
        render_screenshot_card("screenpage")
    render_latest_sections()

elif page.startswith("◷"):
    st.title("Scan History")
    with st.container(border=True):
        render_history()
        if st.session_state.scan_history and st.button("Clear scan history", key="history_page_clear"):
            clear_current_user_history()
            st.rerun()

elif page.startswith("ⓘ  Upload"):
    render_training_page()

else:
    st.title("About PhishGuard")
    st.write("PhishGuard combines URL features, a labeled phishing classifier, active-link checks, QR decoding, and a screenshot research model.")
    st.info("A low-risk result is not proof that a website is safe. Verify unexpected links independently before entering sensitive information.")
    if AI_ENABLED:
        st.caption("GPT-6 explanations are enabled. Scanned URLs and result fields are sent to OpenAI for the explanation.")
    else:
        st.caption("AI explanations are off because OPENAI_API_KEY is not configured. URL, QR, and screenshot analysis remain available.")


st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)
st.caption("🛡️ PhishGuard · Private account history · ML + URL analysis + QR scanning + visual signals")
