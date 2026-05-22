import re, json
from pathlib import Path
import streamlit as st
import streamlit.components.v1 as components
import requests
from datetime import datetime, timedelta

_HERE     = Path(__file__).parent
LOGO_PATH = str(_HERE / "logo.png")

# PAGE CONFIG & STYLES

st.set_page_config(
    page_title="CipherSphere | Secure Vault",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.markdown("""
<style>
.main { background-color: #0e1117; }
.stButton>button {
    width:100%; border-radius:6px; height:3em;
    background-color:#2e7bcf; color:white; font-weight:600;
}
.stButton>button:hover { background-color:#1a5fa8; }
div[data-testid="stMetricValue"] { font-size:20px; color:#2e7bcf; }
.vault-header { font-size:13px; color:#888; text-transform:uppercase; letter-spacing:1px; }
/* Hide the JS activity-tracker input completely */
input[aria-label="_activity_tracker"],
div[data-testid="stTextInput"] input[aria-label="_activity_tracker"] {
    position: absolute !important;
    width: 1px !important;
    height: 1px !important;
    margin: 0 !important;
    padding: 0 !important;
    border: none !important;
    opacity: 0 !important;
    left: -9999px !important;
    top: -9999px !important;
}
</style>
""", unsafe_allow_html=True)
# 1. PASSWORD STRENGTH CHECKER  
class PasswordStrengthChecker:
    STRONG_THRESHOLD = 6
    MIN_LENGTH       = 8
    KEYBOARD_WALKS   = ["qwerty","asdf","zxcv","1234","abcd","password","letmein"]
    REPEATED_RE      = re.compile(r'(.)\1{2,}')

    def check(self, password: str):
        if not password: return False, 0, ["Password cannot be empty."]
        score, tips = 0, []
        length = len(password)
        if length < self.MIN_LENGTH:
            tips.append(f"Too short — use at least {self.MIN_LENGTH} characters.")
        elif length >= 12: score += 2
        else:              score += 1
        has_lower  = any(c.islower()     for c in password)
        has_upper  = any(c.isupper()     for c in password)
        has_digit  = any(c.isdigit()     for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        classes    = sum([has_lower, has_upper, has_digit, has_symbol])
        score     += classes
        if not has_lower:  tips.append("Add lowercase letters (a-z).")
        if not has_upper:  tips.append("Add uppercase letters (A-Z).")
        if not has_digit:  tips.append("Add digits (0-9).")
        if not has_symbol: tips.append("Add symbols (!@#$ etc.).")
        if len(set(password)) >= 10: score += 1
        lp = password.lower()
        for walk in self.KEYBOARD_WALKS:
            if walk in lp:
                score -= 2; tips.append(f"Avoid patterns like '{walk}'."); break
        if self.REPEATED_RE.search(password):
            score -= 1; tips.append("Avoid repeating the same character 3+ times.")
        score     = max(0, score)
        is_strong = score >= self.STRONG_THRESHOLD and length >= self.MIN_LENGTH and classes == 4
        return is_strong, score, ([] if is_strong else tips)

    def label(self, score):
        if score <= 2: return "Weak",   "#e74c3c"
        if score <= 4: return "Fair",   "#e67e22"
        if score <= 6: return "Good",   "#f1c40f"
        return              "Strong", "#2ecc71"

_checker = PasswordStrengthChecker()

def show_strength(pw: str):
    if not pw: return
    _, score, tips = _checker.check(pw)
    lbl, col = _checker.label(score)
    pct = min(100, score * 12)
    st.markdown(
        f"<div style='background:#333;border-radius:4px;height:6px;margin:4px 0 8px'>"
        f"<div style='background:{col};width:{pct}%;height:6px;border-radius:4px'></div>"
        f"</div><span style='color:{col};font-size:12px;font-weight:600'>{lbl}</span>",
        unsafe_allow_html=True
    )
    for t in tips: st.caption(f"⚠ {t}")
# 2. SESSION MANAGER 
class SessionManager:
    DEFAULT_TIMEOUT = 300    
    JS_THROTTLE_MS  = 5_000  

    def touch(self):
        st.session_state.last_activity = datetime.now()

    def sync_from_js(self):
        """Read JS-reported timestamp and update last_activity if newer."""
        raw = st.session_state.get("_js_activity_ts", "")
        if not raw: return
        try:
            js_dt = datetime.fromtimestamp(float(raw))
            cur   = st.session_state.get("last_activity")
            if cur is None or js_dt > cur:
                st.session_state.last_activity = js_dt
        except (ValueError, OSError):
            pass

    def is_locked(self) -> bool:
        last = st.session_state.get("last_activity")
        if last is None: return False
        timeout  = st.session_state.get("auto_lock_val", self.DEFAULT_TIMEOUT)
        return datetime.now() > last + timedelta(seconds=timeout)

    def enforce(self):
        if self.is_locked():
            st.session_state.master_password = ""
            st.session_state.page = "master_password_entry"
            st.warning("🔒 Vault auto-locked due to inactivity. Enter your master password to continue.")
            st.rerun()

    def seconds_remaining(self) -> int:
        last = st.session_state.get("last_activity")
        if last is None:
            return st.session_state.get("auto_lock_val", self.DEFAULT_TIMEOUT)
        timeout   = st.session_state.get("auto_lock_val", self.DEFAULT_TIMEOUT)
        remaining = (last + timedelta(seconds=timeout) - datetime.now()).total_seconds()
        return max(0, int(remaining))

    def fmt(self, s: int) -> str:
        if s <= 0:  return "🔒 LOCKED"
        if s < 60:  return f"⏰ {s}s"
        return f"⏰ {s//60}m {s%60}s"

    def clear(self):
        st.session_state.clear()

_session = SessionManager()


def inject_activity_tracker(timeout_seconds: int):
    """
    Inject the JS inactivity tracker.
    Listens to mouse/keyboard events → writes timestamp to hidden input.
    Reloads page after (timeout - 10)s of silence so Python enforce() fires.
    """
    throttle_ms  = SessionManager.JS_THROTTLE_MS
    reload_ms    = max((timeout_seconds - 10) * 1000, 5_000)
    components.html(f"""
    <script>
    (function(){{
        if(window._csTrackerActive) return;
        window._csTrackerActive = true;
        var lastFired=0, throttle={throttle_ms}, reloadDelay={reload_ms};
        var reloadTimer=null;

        function findInput(){{
            var inputs=window.parent.document.querySelectorAll('input[type="text"]');
            for(var i=0;i<inputs.length;i++){{
                var wrap=inputs[i].closest('[data-testid="stTextInput"]');
                if(wrap){{
                    var lbl=wrap.querySelector('label');
                    if(lbl && lbl.innerText.trim()==='_activity_tracker') return inputs[i];
                }}
            }}
            return null;
        }}

        function onActivity(){{
            var now=Date.now();
            if(now-lastFired<throttle) return;
            lastFired=now;
            var inp=findInput();
            if(inp){{
                var setter=Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype,'value').set;
                setter.call(inp,(now/1000).toFixed(3));
                inp.dispatchEvent(new Event('input',{{bubbles:true}}));
            }}
            clearTimeout(reloadTimer);
            reloadTimer=setTimeout(function(){{
                window.parent.location.reload();
            }}, reloadDelay);
        }}

        var doc=window.parent.document;
        ['mousemove','mousedown','keydown','scroll','touchstart'].forEach(function(e){{
            doc.addEventListener(e, onActivity, {{passive:true}});
        }});
        reloadTimer=setTimeout(function(){{
            window.parent.location.reload();
        }}, reloadDelay);
    }})();
    </script>
    """, height=0)

# 3. API CLIENT

class APIClient:
    BASE = "http://127.0.0.1:5000"

    def _auth(self):
        return {"Authorization": f"Bearer {st.session_state.get('token','')}"}

    def _call(self, method, path, **kw):
        try:
            r = getattr(requests, method)(self.BASE + path, timeout=15, **kw)
            try:    return r.json(), r.status_code
            except: return None, r.status_code
        except requests.exceptions.ConnectionError:
            return {"error": "Cannot reach the server. Is the backend running?"}, 0
        except requests.exceptions.Timeout:
            return {"error": "Request timed out."}, 0

    # Auth
    def login(self, email, pw):
        return self._call("post", "/login", json={"email": email, "password": pw})
    def signup(self, email, pw):
        return self._call("post", "/signup", json={"email": email, "password": pw})

    # OTP — purpose: "verification" | "password_reset"
    def send_otp(self, email, purpose="verification"):
        return self._call("post", "/send_otp", json={"email": email, "purpose": purpose})
    def verify_otp(self, email, otp):
        return self._call("post", "/verify_otp", json={"email": email, "otp": otp})

    # Login password reset
    def request_login_reset(self, email):
        return self._call("post", "/reset_login_password/request", json={"email": email})
    def confirm_login_reset(self, email, otp, new_password):
        return self._call("post", "/reset_login_password/confirm",
                          json={"email": email, "otp": otp, "new_password": new_password})

    # Vault
    def get_vault(self, mp):
        return self._call("get", "/vault", headers=self._auth(), params={"masterPassword": mp})
    def add_entry(self, site, user, pw, mp):
        return self._call("post", "/vault", headers=self._auth(),
                          json={"site": site, "username": user, "password": pw, "masterPassword": mp})
    def update_entry(self, idx, user, pw, mp):
        return self._call("put", "/vault", headers=self._auth(),
                          json={"index": idx, "username": user, "password": pw, "masterPassword": mp})
    def delete_vault(self, mp):
        return self._call("delete", "/vault", headers=self._auth(), json={"masterPassword": mp})

    # Hints
    def save_hints(self, hints):
        return self._call("post", "/hints", headers=self._auth(), json={"hints": hints})
    def get_hints(self):
        return self._call("get", "/hints", headers=self._auth())
    def delete_hints(self):
        return self._call("delete", "/hints", headers=self._auth())

    # Passphrase
    def get_passphrase(self, words=4):
        return self._call("get", "/generate_passphrase", params={"words": words})

    # Account
    def delete_account(self, login_pw, master_pw):
        return self._call("delete", "/account", headers=self._auth(),
                          json={"password": login_pw, "masterPassword": master_pw})

_api = APIClient()

# SESSION STATE DEFAULTS

_defaults = {
    "page":             "home",
    "user_email":       "",
    "master_password":  "",
    "otp_sent":         False,
    "password_vault":   [],
    "auto_lock_val":    300,
    "token":            "",
    "last_activity":    None,
    "nav":              "📂 Vault",
    "_js_activity_ts":  "",
}
for k, v in _defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# Hidden input for JS → Python activity communication
st.text_input("_activity_tracker", key="_js_activity_ts", label_visibility="hidden")

# HELPERS

def logo_home():
    _, c, _ = st.columns([3,2,3])
    with c: st.image(LOGO_PATH, use_container_width=True)

def logo_small():
    _, c, _ = st.columns([4,2,4])
    with c: st.image(LOGO_PATH, use_container_width=True)

def is_auth_err(data): return data.get("error") in ("Token expired","Token missing","Invalid token")
def handle_auth_err():
    st.error("Session expired. Please log in again.")
    _session.clear(); st.rerun()

# PAGE 1 — HOME  (Login / Sign Up / Forgot Login Password)

if st.session_state.page == "home":
    logo_home()
    if st.session_state.pop("_reset_success", False):
        st.success("Password reset successfully! Please log in with your new password.")
    _, c2, _ = st.columns([1,2,1])
    with c2:
        st.markdown(
            "<p style='text-align:center;color:gray;font-size:16px;'>"
            "Securely manage your digital identity</p>", unsafe_allow_html=True
        )
        tab_login, tab_signup = st.tabs(["Login", "Sign Up"])

        # LOGIN 
        with tab_login:
            l_email = st.text_input("Email",    key="login_email")
            l_pass  = st.text_input("Password", key="login_pass",  type="password")
            if st.button("Access Vault", key="login_btn"):
                if not l_email or not l_pass:
                    st.error("Please enter email and password.")
                else:
                    data, code = _api.login(l_email, l_pass)
                    if data and "token" in data:
                        st.session_state.token      = data["token"]
                        st.session_state.user_email = l_email
                        st.session_state.page       = "master_password_entry"
                        st.rerun()
                    elif data:
                        st.error(data.get("error", "Login failed."))

            if st.button("Forgot Login Password?", key="home_forgot_btn"):
                st.session_state.page = "reset_login_request"
                st.rerun()

        # SIGN UP 
        with tab_signup:
            s_email   = st.text_input("Email",            key="signup_email")
            s_pass    = st.text_input("Password",         key="signup_pass",    type="password")
            show_strength(s_pass)
            s_confirm = st.text_input("Confirm Password", key="signup_confirm", type="password")
            if st.button("Create Account", key="signup_btn"):
                if not s_email or not s_pass or not s_confirm:
                    st.error("Please fill in all fields.")
                elif s_pass != s_confirm:
                    st.error("Passwords do not match.")
                else:
                    _, score, tips = _checker.check(s_pass)
                    if score < 3:  # block only Weak (score 0-2)
                        for t in tips: st.error(t)
                    else:
                        data, code = _api.signup(s_email, s_pass)
                        if data and "error" in data:
                            st.error(data["error"])
                        elif data:
                            if data.get("token"): st.session_state.token = data["token"]
                            st.session_state.user_email = s_email
                            st.session_state.page       = "master_password_setup"
                            st.rerun()
    st.stop()


# PAGE 1b — RESET LOGIN PASSWORD: REQUEST

elif st.session_state.page == "reset_login_request":
    logo_small()
    _, c2, _ = st.columns([1,1,1])
    with c2:
        st.markdown("<h2 style='text-align:center;'>🔑 Reset Login Password</h2>", unsafe_allow_html=True)
        st.info(
            "Enter your registered email. We will send a 6-digit code to verify it's you.\n\n"
            "**Your master password and vault data are completely untouched.**"
        )
        r_email = st.text_input("Account Email", key="rlr_email")
        if st.button("Send Reset Code", key="rlr_send_btn"):
            if not r_email:
                st.error("Email is required.")
            else:
                data, code = _api.request_login_reset(r_email)
                if data and "message" in data:
                    st.session_state["_reset_email"] = r_email
                    st.success(data["message"])
                    st.session_state.page = "reset_login_confirm"
                    st.rerun()
                elif data:
                    st.error(data.get("error", "Request failed."))
        st.markdown("---")
        if st.button("← Back to Login", key="rlr_back"):
            st.session_state.page = "home"; st.rerun()
    st.stop()


# PAGE 1c — RESET LOGIN PASSWORD: CONFIRM (OTP + new password)

elif st.session_state.page == "reset_login_confirm":
    logo_small()
    _, c2, _ = st.columns([1,1,1])
    with c2:
        st.markdown("<h2 style='text-align:center;'>🔐 Set New Login Password</h2>", unsafe_allow_html=True)
        r_email = st.session_state.get("_reset_email", "")
        if not r_email:
            st.error("Session lost. Please start again.")
            if st.button("Start again"): st.session_state.page = "reset_login_request"; st.rerun()
        else:
            st.write(f"Enter the 6-digit code sent to **{r_email}**")
            otp_in  = st.text_input("6-digit Code", max_chars=6, key="rlc_otp")
            new_pw  = st.text_input("New Login Password",     key="rlc_pw1", type="password")
            show_strength(new_pw)
            conf_pw = st.text_input("Confirm New Password",   key="rlc_pw2", type="password")

            if st.button("Reset Password", key="rlc_reset_btn"):
                if not otp_in or not new_pw or not conf_pw:
                    st.error("All fields are required.")
                elif new_pw != conf_pw:
                    st.error("Passwords do not match.")
                else:
                    ok, _, tips = _checker.check(new_pw)
                    if not ok:
                        for t in tips: st.error(t)
                    else:
                        data, code = _api.confirm_login_reset(r_email, otp_in, new_pw)
                        if data is None:
                            st.error("No response from server.")
                        elif "message" in data:
                            st.session_state.pop("_reset_email", None)
                            st.session_state["_reset_success"] = True
                            st.session_state.page = "home"
                            st.rerun()
                        else:
                            st.error(data.get("error", "Reset failed. Check your OTP and try again."))

            col1, col2 = st.columns(2)
            with col1:
                if st.button("Resend Code", key="rlc_resend"):
                    data, _ = _api.request_login_reset(r_email)
                    if data and "message" in data: st.success("New code sent!")
                    elif data: st.error(data.get("error"))
            with col2:
                if st.button("← Cancel", key="rlc_cancel"):
                    st.session_state.pop("_reset_email", None)
                    st.session_state.page = "home"; st.rerun()
    st.stop()


# PAGE 2 — MASTER PASSWORD SETUP

elif st.session_state.page == "master_password_setup":
    logo_small()
    _, c2, _ = st.columns([1,1.5,1])
    with c2:
        st.title("🛡️ Secure Your Vault")
        st.info(
            "Your master password **encrypts every entry** in your vault. "
            "It is **never sent to the server** — we cannot recover it. "
            "Write it somewhere safe."
        )

        # Passphrase suggestion
        with st.expander("💡 Need a strong but memorable password? Generate a passphrase"):
            num_w = st.slider("Number of words", 3, 6, 4, key="pp_words_setup")
            if st.button("🎲 Generate Passphrase", key="gen_pp_setup"):
                data, _ = _api.get_passphrase(num_w)
                if data and "passphrase" in data:
                    st.session_state["_pp"]     = data["passphrase"]
                    st.session_state["_pp_bits"] = data["entropy_bits"]
            if st.session_state.get("_pp"):
                st.code(st.session_state["_pp"])
                st.caption(f"Entropy: ~{st.session_state.get('_pp_bits','?')} bits — strong enough for a master password.")

        mp = st.text_input("Create Master Password",  key="mp_create",  type="password")
        show_strength(mp)
        cp = st.text_input("Confirm Master Password", key="mp_confirm", type="password")

        st.markdown("---")
        st.subheader("🔖 Memory Hints (optional)")
        st.caption("Write clues to jog your memory — NOT the password itself. Stored as plain text.")
        h1 = st.text_input("Hint 1 (e.g. 'name of my first pet')",     key="h1_setup")
        h2 = st.text_input("Hint 2 (e.g. 'city where I was born')",    key="h2_setup")
        h3 = st.text_input("Hint 3 (e.g. 'favourite childhood film')", key="h3_setup")

        if st.button("Initialize Vault", key="init_vault_btn"):
            if not mp or not cp:
                st.error("Please fill in both password fields.")
            elif mp != cp:
                st.error("Passwords must match.")
            else:
                ok, _, tips = _checker.check(mp)
                if not ok:
                    for t in tips: st.error(t)
                else:
                    st.session_state.master_password = mp
                    hints = [h for h in [h1, h2, h3] if h.strip()]
                    if hints: _api.save_hints(hints)
                    st.session_state.page = "email_verification"
                    st.rerun()
    st.stop()
# PAGE 3 — MASTER PASSWORD ENTRY  (unlock after login / auto-lock)

elif st.session_state.page == "master_password_entry":
    logo_small()
    _, c2, _ = st.columns([1,1,1])
    with c2:
        st.markdown("<h2 style='text-align:center;'>🔒 Unlock Vault</h2>", unsafe_allow_html=True)
        st.write(f"Logged in as **{st.session_state.user_email}**")

        attempt = st.text_input("Enter Master Password", key="unlock_attempt", type="password")

        hints_data, _ = _api.get_hints()
        if hints_data and hints_data.get("hints"):
            with st.expander("🔖 View your memory hints"):
                for i, h in enumerate(hints_data["hints"], 1):
                    st.write(f"{i}. {h}")

        if st.button("Unlock", key="unlock_btn"):
            if not attempt:
                st.error("Please enter your master password.")
            else:
                data, code = _api.get_vault(attempt)
                if data and "vault" in data:
                    st.session_state.master_password = attempt
                    st.session_state.password_vault  = data["vault"]
                    _session.touch()
                    st.session_state.page = "dashboard"
                    st.rerun()
                elif data and is_auth_err(data):
                    handle_auth_err()
                else:
                    st.error("Incorrect master password.")

        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Logout", key="unlock_logout"):
                _session.clear(); st.rerun()
    st.stop()

# PAGE 4 — EMAIL VERIFICATION

elif st.session_state.page == "email_verification":
    logo_small()
    _, c2, _ = st.columns([1,1,1])
    with c2:
        st.title("📧 Verify Your Email")
        st.write(f"We'll send a 6-digit code to **{st.session_state.user_email}**")

        if not st.session_state.otp_sent:
            if st.button("Send Code", key="send_otp_btn"):
                data, _ = _api.send_otp(st.session_state.user_email, purpose="verification")
                if data and "error" in data:
                    st.error(data["error"])
                else:
                    st.session_state.otp_sent = True
                    st.success("Code sent! Check your inbox.")
                    st.rerun()
        else:
            otp_in = st.text_input("Enter 6-digit Code", max_chars=6, key="otp_input")
            if st.button("Verify & Continue", key="verify_otp_btn"):
                data, _ = _api.verify_otp(st.session_state.user_email, otp_in)
                if data and "message" in data:
                    _session.touch()
                    st.session_state.page = "dashboard"
                    st.rerun()
                elif data:
                    st.error(data.get("error", "Invalid code."))
            if st.button("Resend Code", key="resend_otp_btn"):
                data, _ = _api.send_otp(st.session_state.user_email, purpose="verification")
                if data and "error" in data: st.error(data["error"])
                else: st.session_state.otp_sent = True; st.success("New code sent!")
    st.stop()

# PAGE 5 — DASHBOAR
elif st.session_state.page == "dashboard":
    _session.sync_from_js()
    _session.enforce()
    inject_activity_tracker(st.session_state.auto_lock_val)

    # SIDEBAR
    with st.sidebar:
        st.image(LOGO_PATH, width=100)
        st.markdown(f"### 👤 {st.session_state.user_email}")
        st.radio("", ["📂 Vault", "⚙️ Settings"], key="nav")
        st.divider()
        remaining = _session.seconds_remaining()
        st.caption(_session.fmt(remaining))
        st.divider()
        if st.button("Logout", key="sidebar_logout"):
            _session.clear(); st.rerun()

    # =========================================================================
    # VAULT TAB
    # =========================================================================
    if st.session_state.nav == "📂 Vault":
        logo_small()

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Entries", len(st.session_state.password_vault))
        c2.metric("Vault Status",  "🔐 Encrypted")
        c3.metric("Auto-lock",     _session.fmt(_session.seconds_remaining()))
        st.divider()

        col_add, col_view = st.columns([1, 1.5])

        # ADD ENTRY 
        with col_add:
            st.subheader("➕ Add Entry")
            new_site = st.text_input("Site / Service",   key="vault_site")
            new_user = st.text_input("Username / Email", key="vault_username")
            new_pass = st.text_input("Password",         key="vault_password", type="password")
            if st.button("Save Entry", key="save_btn"):
                if not new_site or not new_user or not new_pass:
                    st.error("All three fields are required.")
                else:
                    _session.touch()
                    data, code = _api.add_entry(
                        new_site, new_user, new_pass,
                        st.session_state.master_password
                    )
                    if code == 200 and data and "message" in data:
                        ref, _ = _api.get_vault(st.session_state.master_password)
                        if ref and "vault" in ref:
                            st.session_state.password_vault = ref["vault"]
                        st.success(data["message"]); st.rerun()
                    elif data and is_auth_err(data): handle_auth_err()
                    elif data: st.error(data.get("error", "Could not save entry."))

        # VIEW VAULT 
        with col_view:
            st.subheader("🔍 Your Vault")

            if not st.session_state.password_vault:
                data, _ = _api.get_vault(st.session_state.master_password)
                if data and "vault" in data:
                    st.session_state.password_vault = data["vault"]
                elif data and is_auth_err(data): handle_auth_err()

            if st.button("🔄 Refresh", key="refresh_vault"):
                _session.touch()
                data, _ = _api.get_vault(st.session_state.master_password)
                if data and "vault" in data:
                    st.session_state.password_vault = data["vault"]; st.rerun()
                elif data and is_auth_err(data): handle_auth_err()

            vault = st.session_state.password_vault
            if not vault:
                st.info("Your vault is empty. Add your first entry on the left.")
            else:
                search   = st.text_input("🔎 Filter entries", key="vault_search",
                                         placeholder="Type a site name…")
                filtered = [e for e in vault if search.strip().lower() in e["site"].lower()] if search.strip() else vault
                st.caption(f"{len(filtered)} of {len(vault)} entries")

                hc1, hc2, hc3, hc4 = st.columns([2,2,2,1])
                for col, lbl in zip([hc1,hc2,hc3,hc4],["Site","Username","Password","Copy"]):
                    col.markdown(f"<span class='vault-header'>{lbl}</span>", unsafe_allow_html=True)
                st.divider()

                for idx, item in enumerate(filtered):
                    ec1, ec2, ec3, ec4 = st.columns([2,2,2,1])
                    ec1.write(item["site"])
                    ec2.write(item["username"])
                    ec3.write("●" * min(len(item["password"]), 20))
                    if ec4.button("📋", key=f"copy_{idx}"):
                        _session.touch()
                        components.html(
                            f"<script>navigator.clipboard.writeText({json.dumps(item['password'])});</script>",
                            height=0
                        )
                        st.toast("Password copied!")

    # SETTINGS TAB

    elif st.session_state.nav == "⚙️ Settings":
        _session.touch()
        logo_small()
        st.title("⚙️ Settings")

        tab_edit, tab_security, tab_danger = st.tabs(
            ["📝 Edit Entries", "🔑 Security", "🚨 Danger Zone"]
        )

        # EDIT ENTRIES 
        with tab_edit:
            vault = st.session_state.get("password_vault", [])
            if not vault:
                st.info("No entries to edit. Add some from the Vault page first.")
            else:
                idx = st.selectbox(
                    "Select entry to edit", range(len(vault)),
                    format_func=lambda x: f"{vault[x]['site']}  ({vault[x]['username']})"
                )
                entry = vault[idx]
                u = st.text_input("Username", value=entry.get("username",""), key="edit_user")
                p = st.text_input("Password", value=entry.get("password",""), key="edit_pass", type="password")
                show_strength(p)
                if st.button("Update Entry", key="update_btn"):
                    _session.touch()
                    data, code = _api.update_entry(idx, u, p, st.session_state.master_password)
                    if data and "message" in data:
                        ref, _ = _api.get_vault(st.session_state.master_password)
                        if ref and "vault" in ref: st.session_state.password_vault = ref["vault"]
                        st.success("Entry updated!"); st.rerun()
                    elif data: st.error(data.get("error", "Update failed."))

        # SECURITY 
        with tab_security:
            st.subheader("Change Master Password")
            st.warning(
                "This updates the master password for this session. "
                "Existing entries will re-encrypt the next time each is updated."
            )
            old_mp  = st.text_input("Current Master Password",     key="sec_old",  type="password")
            new_mp  = st.text_input("New Master Password",         key="sec_new",  type="password")
            show_strength(new_mp)
            conf_mp = st.text_input("Confirm New Master Password", key="sec_conf", type="password")
            if st.button("Update Master Password", key="chg_mp_btn"):
                _session.touch()
                if old_mp != st.session_state.master_password:
                    st.error("Incorrect current master password.")
                elif new_mp != conf_mp:
                    st.error("New passwords do not match.")
                elif not new_mp:
                    st.error("New password cannot be empty.")
                else:
                    ok, _, tips = _checker.check(new_mp)
                    if not ok:
                        for t in tips: st.error(t)
                    else:
                        st.session_state.master_password = new_mp
                        st.success("Master password updated for this session.")

            st.divider()

            # Auto-lock timer
            st.subheader("⏱️ Auto-lock Timer")
            st.caption(
                "Vault locks after this many seconds of **real inactivity** — "
                "no mouse movement, no typing, no scrolling."
            )
            new_val = st.slider(
                "Lock after (seconds)", 30, 3600,
                st.session_state.auto_lock_val, step=30, key="autolock_slider"
            )
            if new_val != st.session_state.auto_lock_val:
                st.session_state.auto_lock_val = new_val
                _session.touch(); st.rerun()
            m, s = st.session_state.auto_lock_val // 60, st.session_state.auto_lock_val % 60
            st.caption(f"Current: **{m}m {s}s** — countdown resets on any interaction.")

        # DANGER ZONE 
        with tab_danger:
            st.error("⚠️ All actions below are **permanent and irreversible**.")

            # Delete entire vault
            st.subheader("🗑️ Delete Entire Vault")
            st.write("Permanently deletes all vault entries. Your account remains active.")
            chk_vault = st.checkbox("I understand all stored passwords will be permanently deleted.",
                                    key="chk_del_vault")
            if st.button("Delete Entire Vault", key="del_vault_btn"):
                if not chk_vault:
                    st.error("Please tick the confirmation checkbox first.")
                else:
                    _session.touch()
                    data, code = _api.delete_vault(st.session_state.master_password)
                    if data and "message" in data:
                        st.session_state.password_vault = []
                        st.success("Vault wiped."); st.rerun()
                    elif data and is_auth_err(data): handle_auth_err()
                    elif data: st.error(data.get("error","Deletion failed."))

            st.divider()

            # Delete account
            st.subheader("💀 Delete Account")
            st.write(
                "Permanently deletes your account, all vault entries, and all hints. "
                "This action **cannot be undone**. "
                "You must confirm with both your login password and master password."
            )
            del_login_pw  = st.text_input("Login Password",  key="del_login_pw",  type="password")
            del_master_pw = st.text_input("Master Password", key="del_master_pw", type="password")
            chk_account   = st.checkbox(
                "I understand my account and all data will be permanently deleted.",
                key="chk_del_account"
            )
            if st.button("💀 Permanently Delete My Account", key="del_account_btn"):
                if not chk_account:
                    st.error("Please tick the confirmation checkbox first.")
                elif not del_login_pw or not del_master_pw:
                    st.error("Both passwords are required to confirm deletion.")
                else:
                    data, code = _api.delete_account(del_login_pw, del_master_pw)
                    if data and "message" in data:
                        st.success(data["message"])
                        _session.clear(); st.rerun()
                    elif data and is_auth_err(data): handle_auth_err()
                    elif data: st.error(data.get("error","Deletion failed."))