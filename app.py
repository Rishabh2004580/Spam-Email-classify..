import streamlit as st
import pickle
import re
import json
import base64
import hashlib
import os
from pathlib import Path
from datetime import datetime

try:
    import bcrypt
    _bcrypt_available = True
except ModuleNotFoundError:
    bcrypt = None
    _bcrypt_available = False

try:
    import nltk
    from nltk.corpus import stopwords
    _nltk_available = True
except ModuleNotFoundError:
    nltk = None
    stopwords = None
    _nltk_available = False

st.set_page_config(page_title="Email Spam Classifier", page_icon="📧", layout="centered")

USERS_FILE = Path("users.json")
HISTORY_FILE = Path("login_history.json")
ADMIN_EMAIL = "risjabhjain123@gmail.com"
ADMIN_NAME = "Admin"
ADMIN_PASSWORD = "Mil@n2004"

if _nltk_available:
    try:
        nltk.data.find("corpora/stopwords")
    except LookupError:
        nltk.download("stopwords", quiet=True)
    stop_words = set(stopwords.words("english"))
else:
    stop_words = set()
    st.warning("NLTK is not installed. Using a minimal tokenizer without stopwords.")

def load_users():
    if USERS_FILE.exists():
        with USERS_FILE.open("r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    return {}

def ensure_admin_user(users):
    admin_key = ADMIN_EMAIL.lower()
    if admin_key not in users:
        users[admin_key] = {
            "name": ADMIN_NAME,
            "password": hash_password(ADMIN_PASSWORD),
            "role": "admin",
        }
        save_users(users)
    elif users[admin_key].get("role") != "admin":
        users[admin_key]["role"] = "admin"
        save_users(users)

def save_users(users):
    with USERS_FILE.open("w", encoding="utf-8") as file_handle:
        json.dump(users, file_handle, indent=2)

def load_history():
    if HISTORY_FILE.exists():
        with HISTORY_FILE.open("r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    return []

def save_history(history):
    with HISTORY_FILE.open("w", encoding="utf-8") as file_handle:
        json.dump(history, file_handle, indent=2)

def record_login(email, name):
    history = load_history()
    history.append({
        "email": email,
        "name": name,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    })
    save_history(history)

def hash_password(password):
    if _bcrypt_available:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return "pbkdf2$" + base64.b64encode(salt).decode("utf-8") + "$" + base64.b64encode(digest).decode("utf-8")

def verify_password(password, hashed):
    if hashed.startswith("pbkdf2$"):
        _, salt_b64, digest_b64 = hashed.split("$", 2)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return digest == expected
    if _bcrypt_available:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    return False

# Load model
model = pickle.load(open("spam_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# Clean text function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^a-zA-Z]', ' ', text)
    words = text.split()
    words = [word for word in words if word not in stop_words]
    return " ".join(words)

SUSPICIOUS_PATTERNS = {
    "payment request": r"\b(pay|payment|fee|invoice|billing|wire|transfer|gift\s*card|crypto|bitcoin)\b",
    "job scam": r"\b(remote position|work from home|hired|offer letter|equipment|training fee)\b",
    "urgency": r"\b(urgent|immediately|act now|limited time|final notice)\b",
    "account/phishing": r"\b(verify|confirm|update|password|login|ssn|social security|bank account)\b",
}

def find_indicators(text):
    hits = []
    for label, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(label)
    return hits

# UI
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

st.markdown(
    """
    <style>
    .stApp {
        background:
            linear-gradient(135deg, rgba(18, 24, 38, 0.08), rgba(18, 24, 38, 0) 45%),
            radial-gradient(circle at top left, #f7f2e9 0%, #eef1f5 45%, #e7ecef 100%);
    }
    .stApp:before {
        content: "";
        position: fixed;
        inset: 0;
        background-image:
            linear-gradient(rgba(17, 24, 39, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(17, 24, 39, 0.05) 1px, transparent 1px);
        background-size: 40px 40px;
        pointer-events: none;
        z-index: 0;
    }
    .auth-card {
        max-width: 520px;
        margin: 24px auto 0 auto;
        padding: 28px;
        background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
        border-radius: 18px;
        box-shadow: 0 18px 40px rgba(25, 30, 40, 0.12);
        border: 1px solid rgba(17, 24, 39, 0.08);
        position: relative;
        z-index: 1;
    }
    .hero-title {
        font-size: 30px;
        font-weight: 800;
        color: #0f172a;
        margin: 6px 0 6px 0;
        letter-spacing: 0.2px;
    }
    .hero-subtitle {
        margin: 0 0 14px 0;
        color: #475569;
        font-size: 14px;
    }
    .brand {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 6px;
    }
    .brand-mark {
        width: 44px;
        height: 44px;
        border-radius: 12px;
        background: linear-gradient(135deg, #0f172a 0%, #334155 100%);
        color: #ffffff;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        letter-spacing: 1px;
    }
    .brand-title {
        font-size: 18px;
        font-weight: 700;
        color: #111827;
        margin: 0;
    }
    .brand-subtitle {
        margin: 0;
        color: #6b7280;
        font-size: 14px;
    }
    .pill-row {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        margin: 6px 0 18px 0;
    }
    .pill {
        background: #e2e8f0;
        color: #0f172a;
        font-size: 12px;
        padding: 6px 10px;
        border-radius: 999px;
        font-weight: 600;
    }
    .stButton button {
        background: #0f172a;
        color: #ffffff;
        border-radius: 10px;
        border: none;
        padding: 8px 16px;
    }
    .stButton button:hover {
        background: #111827;
        color: #ffffff;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.logged_in:
    st.markdown("<div class='auth-card'>", unsafe_allow_html=True)
    st.markdown(
        """
        <div class="brand">
            <div class="brand-mark">SD</div>
            <div>
                <p class="brand-title">Rishabh Jain</p>
                <p class="brand-subtitle">Private access</p>
            </div>
        </div>
        <div class="hero-title">Spam Detector</div>
        <p class="hero-subtitle">Login to scan emails and messages for spam, scams, and phishing.</p>
        <div class="pill-row">
            <span class="pill">Spam</span>
            <span class="pill">Phishing</span>
            <span class="pill">Scam</span>
            <span class="pill">News</span>
            <span class="pill">Promotion</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tabs = st.tabs(["Sign in", "Create account"])
    users = load_users()
    ensure_admin_user(users)

    with tabs[0]:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")

        if submitted:
            user = users.get(email.lower())
            if user and verify_password(password, user["password"]):
                st.session_state.logged_in = True
                st.session_state.user_name = user["name"]
                st.session_state.user_email = email.lower()
                st.session_state.user_role = user.get("role", "user")
                record_login(email.lower(), user["name"])
                st.success("Login successful. Please proceed.")
                st.rerun()
            else:
                st.error("Invalid email or password.")

    with tabs[1]:
        with st.form("signup_form"):
            name = st.text_input("Full name")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create account")

        if submitted:
            email_key = email.lower().strip()
            if not name.strip() or not email_key:
                st.error("Name and email are required.")
            elif "@" not in email_key or "." not in email_key:
                st.error("Please enter a valid email address.")
            elif email_key in users:
                st.error("An account with this email already exists.")
            elif len(password) < 6:
                st.error("Password must be at least 6 characters.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                users[email_key] = {
                    "name": name.strip(),
                    "password": hash_password(password),
                    "role": "user",
                }
                save_users(users)
                st.success("Account created. Please sign in.")

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

st.title("AI Email Spam Classifier")
st.write("Enter subject, sender, and message body for classification.")
user_name = st.session_state.get("user_name", "")
user_email = st.session_state.get("user_email", "")
user_role = st.session_state.get("user_role", "user")
if user_name:
    admin_suffix = " (admin)" if user_role == "admin" else ""
    st.caption(f"Signed in as {user_name}{admin_suffix}")
if st.button("Log out"):
    st.session_state.logged_in = False
    st.rerun()

page = st.sidebar.radio("Navigation", ["Detector", "History"])

if page == "History":
    if user_role != "admin" and user_email.lower() != ADMIN_EMAIL.lower():
        st.warning("History access is restricted to the admin account.")
        st.stop()
    st.header("Login History")
    history = load_history()
    if history:
        st.dataframe(history, use_container_width=True)
    else:
        st.info("No login history available yet.")
    st.stop()

subject_input = st.text_input("Subject (optional)")
sender_input = st.text_input("From (email or name)")
body_input = st.text_area("Email/Message body")

RULE_PATTERNS = {
    "phishing": [
        r"\bverify\b", r"\bconfirm\b", r"\bupdate\b", r"\bpassword\b", r"\blogin\b",
        r"\baccount\b", r"\bssn\b", r"\bbank account\b", r"\botp\b",
        r"पासवर्ड", r"लॉगिन", r"ओटीपी", r"सत्यापित", r"अपडेट", r"खाता", r"बैंक",
    ],
    "scam": [
        r"\bpay\b", r"\bpayment\b", r"\bfee\b", r"\binvoice\b", r"\bwired\b",
        r"\btransfer\b", r"\bgift\s*card\b", r"\bcrypto\b", r"\bbitcoin\b",
        r"\bwon\b", r"\blottery\b", r"\bprize\b", r"\bhired\b", r"\bequipment\b",
        r"इनाम", r"लॉटरी", r"जीत", r"भुगतान", r"फीस", r"रिफंड", r"निवेश", r"कमीशन",
    ],
    "promotion": [
        r"\bfree\b", r"\bdiscount\b", r"\boffer\b", r"\bdeal\b", r"\bcoupon\b",
        r"\bsale\b", r"\blimited time\b", r"\bpromo\b",
        r"ऑफर", r"छूट", r"डिस्काउंट", r"सेल", r"मुफ्त", r"कूपन",
    ],
    "news": [
        r"\bnews\b", r"\bbreaking\b", r"\bheadline\b", r"\breported\b",
        r"\bpress release\b", r"\bannouncement\b",
        r"समाचार", r"खबर", r"ब्रेकिंग", r"रिपोर्ट", r"सूचना",
    ],
}

def score_categories(text):
    scores = {}
    for category, patterns in RULE_PATTERNS.items():
        count = 0
        for pattern in patterns:
            if re.search(pattern, text, flags=re.IGNORECASE):
                count += 1
        if count:
            scores[category] = count
    return scores

if st.button("Predict"):
    parts = [subject_input, sender_input, body_input]
    full_text = " ".join([part for part in parts if part.strip()]).strip()
    if not full_text:
        st.warning("Please enter a message before predicting.")
    else:
        category_scores = score_categories(full_text)
        cleaned = clean_text(full_text)
        vector = vectorizer.transform([cleaned])
        prediction = model.predict(vector)
        spam_prob = None
        if hasattr(model, "predict_proba"):
            spam_prob = float(model.predict_proba(vector)[0][1])

        is_spam = bool(prediction[0] == 1)
        primary_label = "normal"
        if category_scores:
            primary_label = max(category_scores, key=category_scores.get)
        if is_spam and primary_label == "normal":
            primary_label = "spam"

        if primary_label in {"phishing", "scam"}:
            st.error(f"Primary label: {primary_label.upper()}")
            st.error("Likely fake message or email.")
        elif primary_label == "promotion":
            st.warning("Primary label: PROMOTION")
            st.info("Probably not fake, but promotional.")
        elif primary_label == "news":
            st.info("Primary label: NEWS")
            st.info("Looks like news content.")
        elif primary_label == "spam":
            st.error("Primary label: SPAM")
            st.error("Likely fake message or email.")
        else:
            st.success("Primary label: NORMAL")
            st.info("No strong signs of a fake message.")

        if spam_prob is not None:
            st.caption(f"Model spam probability: {spam_prob:.0%}")
        if category_scores:
            detected = ", ".join(sorted(category_scores.keys()))
            st.caption("Rule-based categories detected: " + detected)

        summary_lines = []
        summary_lines.append(f"Category: {primary_label.upper()}")
        if spam_prob is not None:
            summary_lines.append(f"Spam probability: {spam_prob:.0%}")
        if category_scores:
            summary_lines.append("Matched categories: " + ", ".join(sorted(category_scores.keys())))
        else:
            summary_lines.append("Matched categories: None")

        with st.expander("Detailed output", expanded=True):
            st.write("\n".join(summary_lines))
            if primary_label in {"phishing", "scam", "spam"}:
                st.write("Recommendation: Do not click links or share personal data.")
            elif primary_label == "promotion":
                st.write("Recommendation: Treat as marketing and verify the sender if unsure.")
            elif primary_label == "news":
                st.write("Recommendation: Confirm with trusted sources if the claim is important.")
            else:
                st.write("Recommendation: Message looks normal based on current checks.")

        st.session_state.last_label = primary_label.upper()
        st.session_state.last_prob = spam_prob