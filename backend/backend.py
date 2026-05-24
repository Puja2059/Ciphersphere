from flask import Flask, request, jsonify
import hashlib, os, re, base64, smtplib, secrets, time, threading
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from email.mime.text import MIMEText
import mysql.connector
from dotenv import load_dotenv
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from dataclasses import dataclass
from collections import deque

load_dotenv()

app = Flask(__name__)

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is not set.\n"
        "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\""
    )

# 1. PASSWORD STRENGTH CHECKER
class PasswordStrengthChecker:
    STRONG_THRESHOLD = 6
    MIN_LENGTH       = 8
    KEYBOARD_WALKS   = ["qwerty", "asdf", "zxcv", "1234", "abcd", "password", "letmein"]
    REPEATED_PATTERN = re.compile(r'(.)\1{2,}')

    def check(self, password: str):
        if not password:
            return False, 0, ["Password cannot be empty."]
        score, feedback = 0, []
        length = len(password)
        if length < self.MIN_LENGTH:
            feedback.append(f"Too short — use at least {self.MIN_LENGTH} characters.")
        elif length >= 12:
            score += 2
        else:
            score += 1
        has_lower   = any(c.islower()     for c in password)
        has_upper   = any(c.isupper()     for c in password)
        has_digit   = any(c.isdigit()     for c in password)
        has_symbol  = any(not c.isalnum() for c in password)
        class_count = sum([has_lower, has_upper, has_digit, has_symbol])
        score      += class_count
        if not has_lower:  feedback.append("Add lowercase letters (a-z).")
        if not has_upper:  feedback.append("Add uppercase letters (A-Z).")
        if not has_digit:  feedback.append("Add digits (0-9).")
        if not has_symbol: feedback.append("Add symbols (!@#$ etc.).")
        if len(set(password)) >= 10:
            score += 1
        lower_pw = password.lower()
        for pattern in self.KEYBOARD_WALKS:
            if pattern in lower_pw:
                score -= 2
                feedback.append(f"Avoid predictable patterns like '{pattern}'.")
                break
        if self.REPEATED_PATTERN.search(password):
            score -= 1
            feedback.append("Avoid repeating the same character 3+ times in a row.")
        score     = max(0, score)
        is_strong = (score >= self.STRONG_THRESHOLD
                     and length >= self.MIN_LENGTH
                     and class_count == 4)
        if is_strong:
            feedback = []
        return is_strong, score, feedback


_strength_checker = PasswordStrengthChecker()

def is_strong_password(p: str) -> bool:
    ok, _, _ = _strength_checker.check(p)
    return ok

def password_feedback(p: str) -> list:
    _, _, tips = _strength_checker.check(p)
    return tips

# 2. PASSPHRASE GENERATOR  
WORDLIST = [
    "apple","arrow","atlas","bacon","badge","baker","beach","blade","blank",
    "blast","blaze","blend","bless","block","bloom","blown","blues","blunt",
    "board","bones","boost","booth","bound","boxer","brace","brain","brand",
    "brave","bread","break","breed","brick","bride","brief","brine","bring",
    "brisk","broad","broke","brook","brush","build","built","bulge","burst",
    "camel","candy","carry","carve","catch","cedar","chain","chair","chalk",
    "chart","chase","cheap","check","cheek","chess","chest","chief","child",
    "chili","china","chips","chord","civil","claim","clamp","class","clean",
    "clear","clerk","click","cliff","climb","cling","clock","clone","close",
    "cloth","cloud","clove","coach","coast","cobra","coral","count","court",
    "cover","craft","crane","crash","cream","creek","crest","crime","crisp",
    "cross","crown","crush","crust","crypt","cubic","curve","cycle","daily",
    "dairy","daisy","dance","delta","dense","depot","depth","derby","digit",
    "dingo","disco","ditch","diver","dodge","donor","doubt","dough","draft",
    "drain","dream","dress","drift","drill","drink","drive","drone","drops",
    "drums","dryer","eagle","earth","eight","elder","elite","empty","enter",
    "envoy","equal","error","essay","event","exact","exist","extra","fable",
    "faith","false","fancy","fatal","fault","feast","fence","ferry","fetch",
    "fever","fiber","field","fifth","fifty","fight","final","first","fixed",
    "flame","flask","fleet","flesh","flint","float","flood","floor","flora",
    "flour","flute","focal","folks","force","forge","forth","forum","found",
    "frame","frank","fraud","fresh","front","frost","froze","fruit","fully",
    "funky","ghost","giant","given","glade","glass","globe","gloom","glory",
    "gloss","glove","grace","grade","grain","grand","grant","grape","grasp",
    "grass","grave","great","greed","green","greet","grief","grind","groan",
    "group","grove","grown","guard","guess","guest","guide","guild","gulch",
    "habit","happy","harsh","haven","heart","heavy","hedge","helix","herbs",
    "heron","hinge","hippo","holly","honey","honor","horse","hotel","hound",
    "house","human","humid","humor","hyena","image","index","indie","inert",
    "inlet","input","ivory","jewel","joint","joker","judge","juice","jumbo",
    "karma","kayak","knack","knife","knock","known","koala","label","lance",
    "large","laser","later","latch","layer","learn","lease","ledge","lemon",
    "level","light","lilac","limit","linen","liver","local","lodge","logic",
    "lotus","lower","lucid","lunar","lunch","magic","major","maker","manor",
    "maple","march","marsh","mason","match","mayor","media","mercy","metal",
    "metro","micro","might","minor","minus","mixed","model","moist","money",
    "month","moral","motor","motto","mount","mouse","mouth","movie","music",
    "naval","nerve","night","ninja","noble","noise","north","novel","nurse",
    "ocean","offer","often","olive","onset","opera","orbit","order","organ",
    "otter","oxide","ozone","paint","panda","panel","paper","paste","patch",
    "pause","peace","peach","pearl","pedal","penny","perch","phase","phone",
    "photo","piano","pilot","pinch","pixel","pizza","place","plain","plane",
    "plant","plaza","plumb","plume","point","polar","pouch","power","press",
    "price","pride","prime","print","prior","prism","prize","probe","proof",
    "prose","proud","prove","proxy","pulse","pupil","queen","quest","quick",
    "quiet","quota","quote","radar","radio","rainy","rally","ranch","range",
    "rapid","raven","reach","realm","rebel","relax","relay","renew","repay",
    "reply","rider","ridge","rifle","right","rigid","risky","rival","river",
    "robin","robot","rocky","rough","round","route","rowdy","royal","ruler",
    "rusty","saint","salad","sauce","scale","scent","score","scout","screw",
    "seize","sense","serve","setup","seven","shade","shaft","shake","shame",
    "shape","share","shark","sharp","sheep","sheet","shelf","shell","shift",
    "shine","shirt","shock","shore","short","shout","sight","since","sixth",
    "skill","slate","sleep","slick","slide","sling","slope","sloth","smart",
    "smash","smell","smith","smoke","snake","solar","solid","solve","sorry",
    "south","space","spark","speak","speed","spend","spice","spike","spine",
    "split","spoon","sport","spray","squad","squid","stack","staff","stage",
    "stain","stamp","stand","stark","start","state","steam","steel","steer",
    "stern","stick","still","stock","stone","store","storm","story","stout",
    "stove","strap","straw","strip","stuck","study","style","sugar","suite",
    "sunny","super","surge","swamp","sweep","sweet","swift","swing","sword",
    "syrup","table","talon","taste","teach","tense","theme","thick","thing",
    "think","third","thorn","three","tiger","tight","timer","titan","title",
    "today","token","torch","total","touch","tough","towel","tower","toxic",
    "track","trade","trail","train","trait","trash","tread","treat","trend",
    "trial","tribe","trick","trout","truck","truly","trunk","trust","truth",
    "tulip","tunic","twist","ultra","uncle","under","union","unity","until",
    "upper","urban","usage","usual","valid","value","valve","vapor","vault",
    "vigor","vista","vital","vivid","vocal","voice","voter","wafer","waltz",
    "waste","watch","water","weave","wedge","weird","whale","wheat","wheel",
    "white","whole","wider","windy","witty","world","worry","worth","wound",
    "wrath","wrist","write","yacht","yield","young","youth","zebra","zonal",
]


class PassphraseGenerator:
    """
    Generates memorable but cryptographically strong passphrases.
    No external library — built from scratch.
    Example output: "Forest-Hammer-Dragon-Castle-47"
    """
    def generate(self, num_words=4, separator="-", capitalise=True, add_digit=True) -> str:
        words = [secrets.choice(WORDLIST) for _ in range(num_words)]
        if capitalise:
            words = [w.capitalize() for w in words]
        phrase = separator.join(words)
        if add_digit:
            phrase += separator + str(secrets.randbelow(90) + 10)
        return phrase

    def entropy_bits(self, num_words: int) -> float:
        import math
        return round(num_words * math.log2(len(WORDLIST)), 1)


_passphrase_gen = PassphraseGenerator()

# 3. INPUT VALIDATOR 
class InputValidator:
    _EMAIL_RE = re.compile(
        r'^[a-zA-Z0-9][a-zA-Z0-9._%+\-]{0,62}'
        r'@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,}$'
    )
    _OTP_RE   = re.compile(r'^\d{6}$')
    _HINT_RE  = re.compile(r'^[^<>]{1,200}$')

    MAX_SITE_LEN     = 255
    MAX_USERNAME_LEN = 255
    MAX_PASSWORD_LEN = 1024
    MAX_HINTS        = 3
    MAX_HINT_LEN     = 200

    def email(self, v):
        if not v or not isinstance(v, str): return False, "Email is required."
        v = v.strip()
        if len(v) > 254:                    return False, "Email is too long."
        if not self._EMAIL_RE.match(v):     return False, "Email format is invalid."
        return True, ""

    def otp(self, v):
        if not v or not isinstance(v, str):      return False, "OTP is required."
        if not self._OTP_RE.match(v.strip()):    return False, "OTP must be exactly 6 digits."
        return True, ""

    def site(self, v):
        if not v or not isinstance(v, str):                 return False, "Site name is required."
        if len(v.strip()) > self.MAX_SITE_LEN:              return False, "Site name too long."
        return True, ""

    def username(self, v):
        if not v or not isinstance(v, str):                 return False, "Username is required."
        if len(v.strip()) > self.MAX_USERNAME_LEN:          return False, "Username too long."
        return True, ""

    def vault_password(self, v):
        if not v or not isinstance(v, str):                 return False, "Password is required."
        if len(v) > self.MAX_PASSWORD_LEN:                  return False, "Password too long."
        return True, ""

    def hint(self, v):
        if not v or not isinstance(v, str):                 return False, "Hint is required."
        v = v.strip()
        if len(v) > self.MAX_HINT_LEN:                      return False, "Hint too long (max 200 chars)."
        if not self._HINT_RE.match(v):                      return False, "Hint must not contain < or >."
        return True, ""

    def entry_index(self, value, max_index):
        if value is None: return False, "Entry index is required."
        try:
            idx = int(value)
        except (TypeError, ValueError):
            return False, "Entry index must be an integer."
        if not (0 <= idx < max_index):
            return False, f"Entry index {idx} out of range."
        return True, ""


_validator = InputValidator()

# 4. OTP STORE 
class OTPStore:
    TTL_SECONDS  = 300  
    MAX_ATTEMPTS = 5

    def __init__(self):
        self._store = {}
        self._lock  = threading.Lock()

    def _now(self): return datetime.now(tz=timezone.utc)

    def generate(self, email: str) -> str:
        otp    = f"{secrets.randbelow(900_000) + 100_000}"
        expiry = self._now() + timedelta(seconds=self.TTL_SECONDS)
        with self._lock:
            self._store[email] = {"otp": otp, "expiry": expiry, "attempts": 0}
        return otp

    def verify(self, email: str, candidate: str) -> tuple:
        with self._lock:
            entry = self._store.get(email)
            if entry is None:
                return False, "No OTP requested for this email."
            if self._now() > entry["expiry"]:
                del self._store[email]
                return False, "OTP has expired. Please request a new one."
            if entry["attempts"] >= self.MAX_ATTEMPTS:
                del self._store[email]
                return False, "Too many failed attempts. Please request a new OTP."
            if secrets.compare_digest(entry["otp"], candidate.strip()):
                del self._store[email]
                return True, ""
            entry["attempts"] += 1
            remaining = self.MAX_ATTEMPTS - entry["attempts"]
            return False, f"Invalid OTP. {remaining} attempt(s) remaining."

    def purge_expired(self):
        now = self._now()
        with self._lock:
            expired = [k for k, v in self._store.items() if now > v["expiry"]]
            for k in expired: del self._store[k]


otp_store = OTPStore()
# 5. RATE LIMITER 
class SlidingWindowRateLimiter:
    def __init__(self):
        self._windows = {}
        self._lock    = threading.Lock()

    def check(self, key: str, max_requests: int, window_seconds: int) -> tuple:
        now    = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            if key not in self._windows:
                self._windows[key] = deque()
            dq = self._windows[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                return False, int(dq[0] + window_seconds - now) + 1
            dq.append(now)
            return True, 0


_rate_limiter = SlidingWindowRateLimiter()


def rate_limit(max_requests: int, window_seconds: int):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip  = request.remote_addr or "unknown"
            key = f"{ip}:{f.__name__}"
            ok, retry = _rate_limiter.check(key, max_requests, window_seconds)
            if not ok:
                return jsonify({"error": f"Too many requests. Retry in {retry}s."}), 429
            return f(*args, **kwargs)
        return wrapper
    return decorator

# 6. VAULT ENTRY  
@dataclass
class VaultEntry:
    site: str; username: str; password: str

    def __post_init__(self):
        for name, val, vfn in [
            ("site",     self.site,     _validator.site),
            ("username", self.username, _validator.username),
            ("password", self.password, _validator.vault_password),
        ]:
            ok, err = vfn(val)
            if not ok: raise ValueError(f"VaultEntry.{name}: {err}")

    def to_dict(self): return {"site": self.site, "username": self.username, "password": self.password}
# DB HELPERS

_db_initialised = False

def _init_tables(conn):
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INT          AUTO_INCREMENT PRIMARY KEY,
            email         VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255)        NOT NULL,
            salt          VARCHAR(64)         NOT NULL,
            created_at    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email (email)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS vaults (
            id                 INT          AUTO_INCREMENT PRIMARY KEY,
            email              VARCHAR(255) NOT NULL,
            site               VARCHAR(255) NOT NULL,
            username           VARCHAR(255) NOT NULL,
            encrypted_password TEXT         NOT NULL,
            vault_salt         VARCHAR(64)  NOT NULL,
            created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE,
            INDEX idx_vault_email (email)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_log (
            id           INT          AUTO_INCREMENT PRIMARY KEY,
            email        VARCHAR(255) NOT NULL,
            requested_at DATETIME     NOT NULL,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE,    
            INDEX idx_reset_email (email)
        )
    """)


    cur.execute("""
        CREATE TABLE IF NOT EXISTS master_password_hints (
            id         INT          AUTO_INCREMENT PRIMARY KEY,
            email      VARCHAR(255) NOT NULL,
            hint_order TINYINT      NOT NULL DEFAULT 1,
            hint_text  VARCHAR(200) NOT NULL,
            created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE,
            INDEX idx_hint_email (email)
        )
    """)

    conn.commit()
    cur.close()


def get_db():
    global _db_initialised
    conn = mysql.connector.connect(
        host               = os.getenv("DB_HOST",     "localhost"),
        port               = int(os.getenv("DB_PORT", "3306")),
        user               = os.getenv("DB_USER"),
        password           = os.getenv("DB_PASSWORD"),
        database           = os.getenv("DB_NAME"),
        connection_timeout = 30,
    )
    if not _db_initialised:
        _init_tables(conn)
        _db_initialised = True
    return conn

# CRYPTO HELPERS
def derive_key(master_password: str, salt: str) -> bytes:
    return PBKDF2(master_password, salt.encode(), dkLen=32, count=100_000)

def encrypt_password(key: bytes, plaintext: str) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ct).decode()

def decrypt_password(key: bytes, enc: str) -> str:
    raw = base64.b64decode(enc)
    nonce, tag, ct = raw[:16], raw[16:32], raw[32:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag).decode()

def hash_login_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000).hex()

# JWT HELPERS
def make_token(email: str) -> str:
    return jwt.encode(
        {"email": email,
         "exp": datetime.now(tz=timezone.utc) + timedelta(hours=8),
         "iat": datetime.now(tz=timezone.utc)},
        SECRET_KEY, algorithm="HS256"
    )

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token missing"}), 401
        raw = auth.split(" ", 1)[1].strip()
        if not raw:
            return jsonify({"error": "Token missing"}), 401
        try:
            decoded = jwt.decode(raw, SECRET_KEY, algorithms=["HS256"])
            email   = decoded["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(email, *args, **kwargs)
    return decorated
# SMTP HELPER

def send_email(to: str, subject: str, body: str):
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"]    = os.environ.get("SMTP_FROM", "ciphersphere147@gmail.com")
    msg["To"]      = to
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
        s.login(os.environ.get("SMTP_USER", "ciphersphere147@gmail.com"),
                os.environ.get("GMAIL_APP_PASSWORD"))
        s.send_message(msg)

# GENERATE PASSPHRASE 
@app.route("/generate_passphrase", methods=["GET"])
@rate_limit(30, 60)
def generate_passphrase():
    try:
        num_words = max(3, min(8, int(request.args.get("words", 4))))
    except ValueError:
        num_words = 4
    sep = request.args.get("separator", "-")
    if sep not in ("-", "_", ".", " "): sep = "-"
    phrase = _passphrase_gen.generate(num_words, sep, capitalise=True, add_digit=True)
    return jsonify({
        "passphrase":   phrase,
        "entropy_bits": _passphrase_gen.entropy_bits(num_words),
        "word_count":   num_words,
        "tip": "Read it a few times then type from memory — strong enough for a master password."
    })


# SEND OTP  (email verification + login-password reset) 
@app.route("/send_otp", methods=["POST"])
@rate_limit(5, 60)
def send_otp():
    data    = request.get_json(silent=True) or {}
    email   = data.get("email", "").strip()
    purpose = data.get("purpose", "verification")  

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400

    # For password reset OTP the user must already exist
    if purpose == "password_reset":
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone():
                return jsonify({"message": "If that email is registered, a code has been sent."})
        finally:
            cur.close(); conn.close()

    otp = otp_store.generate(email)
    subject = ("CipherSphere — Email Verification"
               if purpose == "verification"
               else "CipherSphere — Login Password Reset")
    body = (
        f"Your CipherSphere code is: {otp}\n\n"
        f"It expires in {OTPStore.TTL_SECONDS // 60} minutes.\n"
        f"Do not share this code with anyone."
    )
    try:
        send_email(email, subject, body)
    except Exception as e:
        print(f"[send_otp] SMTP error: {e}")
        return jsonify({"error": "Failed to send code. Please try again."}), 500

    return jsonify({"message": "Code sent successfully."})


# VERIFY OTP 
@app.route("/verify_otp", methods=["POST"])
@rate_limit(10, 60)
def verify_otp():
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    code  = str(data.get("otp", "")).strip()

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400
    ok, err = _validator.otp(code)
    if not ok: return jsonify({"error": err}), 400

    ok, err = otp_store.verify(email, code)
    if not ok: return jsonify({"error": err}), 400

    return jsonify({"message": "OTP verified successfully."})


# SIGNUP 
@app.route('/signup', methods=['POST'])
@rate_limit(10, 3600)
def signup():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400
    if not password: return jsonify({"error": "Password is required."}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Password too weak.", "tips": password_feedback(password)}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
        if cur.fetchone():
            return jsonify({"error": "An account with that email already exists."}), 400
        salt = os.urandom(16).hex()
        cur.execute(
            "INSERT INTO users (email, password_hash, salt) VALUES (%s, %s, %s)",
            (email, hash_login_password(password, salt), salt)
        )
        conn.commit()
    finally:
        cur.close(); conn.close()

    return jsonify({"message": "Account created successfully.", "token": make_token(email)})


# LOGIN 
@app.route('/login', methods=['POST'])
@rate_limit(10, 60)
def login():
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400
    if not password: return jsonify({"error": "Password is required."}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
        user = cur.fetchone()
    finally:
        cur.close(); conn.close()

    # Constant-time path 
    dummy = hash_login_password(password, "dummy_salt_padding_00000000000000")
    if not user:
        secrets.compare_digest(dummy, "0" * len(dummy))
        return jsonify({"error": "Invalid email or password."}), 401

    if not secrets.compare_digest(hash_login_password(password, user["salt"]),
                                   user["password_hash"]):
        return jsonify({"error": "Invalid email or password."}), 401

    return jsonify({"token": make_token(email)})


#RESET LOGIN PASSWORD (Step 1: request OTP) 
@app.route('/reset_login_password/request', methods=['POST'])
@rate_limit(5, 3600)
def request_login_password_reset():
    data  = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
        exists = cur.fetchone()
    finally:
        cur.close(); conn.close()

    if not exists:
        return jsonify({"message": "If that email is registered, a reset code has been sent."})

    otp = otp_store.generate(email)
    try:
        send_email(
            to      = email,
            subject = "CipherSphere — Login Password Reset",
            body    = (
                f"Your CipherSphere login password reset code is: {otp}\n\n"
                f"It expires in {OTPStore.TTL_SECONDS // 60} minutes.\n\n"
                f"NOTE: This resets your LOGIN password only.\n"
                f"Your master password and vault data are NOT affected.\n\n"
                f"If you did not request this, you can safely ignore this email.\n\n"
                f"— The CipherSphere Team"
            )
        )
    except Exception as e:
        print(f"[reset_login_password/request] SMTP error: {e}")
        return jsonify({"error": "Failed to send reset code. Please try again."}), 500

    # Log the request for audit purposes
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO password_reset_log (email, requested_at) VALUES (%s, %s)",
            (email, datetime.now(tz=timezone.utc))
        )
        conn.commit()
    finally:
        cur.close(); conn.close()

    return jsonify({"message": "If that email is registered, a reset code has been sent."})


# RESET LOGIN PASSWORD (Step 2: verify OTP + set new password) 
@app.route('/reset_login_password/confirm', methods=['POST'])
@rate_limit(10, 3600)
def confirm_login_password_reset():
    data         = request.get_json(silent=True) or {}
    email        = data.get("email", "").strip()
    otp_code     = str(data.get("otp", "")).strip()
    new_password = data.get("new_password", "")

    ok, err = _validator.email(email)
    if not ok: return jsonify({"error": err}), 400

    ok, err = _validator.otp(otp_code)
    if not ok: return jsonify({"error": err}), 400

    if not new_password:
        return jsonify({"error": "New password is required."}), 400
    if not is_strong_password(new_password):
        return jsonify({"error": "Password too weak.", "tips": password_feedback(new_password)}), 400

    # Verify OTP 
    ok, err = otp_store.verify(email, otp_code)
    if not ok: return jsonify({"error": err}), 400

    conn = get_db()
    cur  = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
        if not cur.fetchone():
            return jsonify({"error": "User not found."}), 404

        new_salt = os.urandom(16).hex()
        new_hash = hash_login_password(new_password, new_salt)

        cur.execute(
            "UPDATE users SET password_hash=%s, salt=%s WHERE LOWER(email)=LOWER(%s)",
            (new_hash, new_salt, email)
        )
        conn.commit()
    finally:
        cur.close(); conn.close()

    return jsonify({
        "message": (
            "Login password reset successfully. "
            "Your vault and master password are unchanged. "
            "Please log in with your new password."
        )
    })


# GET VAULT 
@app.route('/vault', methods=['GET'])
@token_required
def get_vault(email):
    master_password = request.args.get("masterPassword", "")
    if not master_password:
        return jsonify({"error": "masterPassword is required."}), 400
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT site, username, encrypted_password, vault_salt "
                "FROM vaults WHERE email=%s ORDER BY id", (email,)
            )
            rows = cur.fetchall()
        finally:
            cur.close(); conn.close()

        result = []
        for r in rows:
            key  = derive_key(master_password, r["vault_salt"])
            text = decrypt_password(key, r["encrypted_password"])
            result.append(VaultEntry(r["site"], r["username"], text).to_dict())
        return jsonify({"vault": result})
    except Exception as e:
        print(f"[get_vault] {e}")
        return jsonify({"error": "Wrong master password or decryption failed."}), 400


# ADD VAULT ENTRY 
@app.route('/vault', methods=['POST'])
@token_required
def add_vault(email):
    data = request.get_json(silent=True) or {}
    mp   = data.get("masterPassword", "")
    site = data.get("site", "").strip()
    user = data.get("username", "").strip()
    pw   = data.get("password", "")

    if not mp: return jsonify({"error": "masterPassword is required."}), 400
    for name, val, fn in [("site", site, _validator.site),
                           ("username", user, _validator.username),
                           ("password", pw, _validator.vault_password)]:
        ok, err = fn(val)
        if not ok: return jsonify({"error": err}), 400

    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT encrypted_password, vault_salt FROM vaults WHERE email=%s LIMIT 1",
                (email,)
            )
            existing = cur.fetchone()
            if existing:
                try:
                    decrypt_password(derive_key(mp, existing["vault_salt"]),
                                     existing["encrypted_password"])
                except Exception:
                    return jsonify({"error": "Invalid master password."}), 400
            vs  = os.urandom(16).hex()
            enc = encrypt_password(derive_key(mp, vs), pw)
            cur.execute(
                "INSERT INTO vaults (email, site, username, encrypted_password, vault_salt) "
                "VALUES (%s, %s, %s, %s, %s)",
                (email, site, user, enc, vs)
            )
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Entry saved successfully."})
    except Exception as e:
        print(f"[add_vault] {e}")
        return jsonify({"error": "Internal server error."}), 500


# UPDATE VAULT ENTRY 
@app.route('/vault', methods=['PUT'])
@token_required
def update_vault(email):
    data = request.get_json(silent=True) or {}
    mp   = data.get("masterPassword", "")
    idx  = data.get("index")
    new_user = data.get("username", "").strip()
    new_pw   = data.get("password", "")

    if not mp: return jsonify({"error": "masterPassword is required."}), 400
    for name, val, fn in [("username", new_user, _validator.username),
                           ("password", new_pw, _validator.vault_password)]:
        ok, err = fn(val)
        if not ok: return jsonify({"error": err}), 400

    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT id, encrypted_password, vault_salt FROM vaults "
                "WHERE email=%s ORDER BY id", (email,)
            )
            rows = cur.fetchall()
            ok, err = _validator.entry_index(idx, len(rows))
            if not ok: return jsonify({"error": err}), 400
            target = rows[int(idx)]
            try:
                decrypt_password(derive_key(mp, target["vault_salt"]),
                                 target["encrypted_password"])
            except Exception:
                return jsonify({"error": "Invalid master password."}), 400
            nvs  = os.urandom(16).hex()
            nenc = encrypt_password(derive_key(mp, nvs), new_pw)
            cur.execute(
                "UPDATE vaults SET username=%s, encrypted_password=%s, vault_salt=%s "
                "WHERE id=%s",
                (new_user, nenc, nvs, target["id"])
            )
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Entry updated successfully."})
    except Exception as e:
        print(f"[update_vault] {e}")
        return jsonify({"error": "Internal server error."}), 500


# DELETE VAULT 
@app.route('/vault', methods=['DELETE'])
@token_required
def delete_vault(email):
    data = request.get_json(silent=True) or {}
    mp   = data.get("masterPassword", "")
    if not mp: return jsonify({"error": "masterPassword is required."}), 400
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT encrypted_password, vault_salt FROM vaults WHERE email=%s LIMIT 1",
                (email,)
            )
            sample = cur.fetchone()
            if sample:
                try:
                    decrypt_password(derive_key(mp, sample["vault_salt"]),
                                     sample["encrypted_password"])
                except Exception:
                    return jsonify({"error": "Invalid master password."}), 400
            cur.execute("DELETE FROM vaults WHERE email=%s", (email,))
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Vault deleted successfully."})
    except Exception as e:
        print(f"[delete_vault] {e}")
        return jsonify({"error": "Internal server error."}), 500


# SAVE HINTS 
@app.route('/hints', methods=['POST'])
@token_required
def save_hints(email):
    """
    Save memory-aid hints for the master password.
    Zero-knowledge preserved: hints are plain text written by the user.
    They are NEVER derived from the master password or used to decrypt anything.
    """
    data  = request.get_json(silent=True) or {}
    hints = data.get("hints", [])
    if not isinstance(hints, list) or len(hints) == 0:
        return jsonify({"error": "At least one hint is required."}), 400
    if len(hints) > _validator.MAX_HINTS:
        return jsonify({"error": f"Maximum {_validator.MAX_HINTS} hints allowed."}), 400
    clean = []
    for i, h in enumerate(hints, 1):
        ok, err = _validator.hint(h)
        if not ok: return jsonify({"error": f"Hint {i}: {err}"}), 400
        clean.append(h.strip())
    try:
        conn = get_db()
        cur  = conn.cursor()
        try:
            cur.execute("DELETE FROM master_password_hints WHERE email=%s", (email,))
            for order, text in enumerate(clean, 1):
                cur.execute(
                    "INSERT INTO master_password_hints (email, hint_order, hint_text) "
                    "VALUES (%s, %s, %s)", (email, order, text)
                )
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": f"{len(clean)} hint(s) saved."})
    except Exception as e:
        print(f"[save_hints] {e}")
        return jsonify({"error": "Internal server error."}), 500


# GET HINTS 
@app.route('/hints', methods=['GET'])
@token_required
def get_hints(email):
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute(
                "SELECT hint_text FROM master_password_hints "
                "WHERE email=%s ORDER BY hint_order", (email,)
            )
            rows = cur.fetchall()
        finally:
            cur.close(); conn.close()
        return jsonify({"hints": [r["hint_text"] for r in rows]})
    except Exception as e:
        print(f"[get_hints] {e}")
        return jsonify({"error": "Internal server error."}), 500


# DELETE HINTS 
@app.route('/hints', methods=['DELETE'])
@token_required
def delete_hints(email):
    try:
        conn = get_db()
        cur  = conn.cursor()
        try:
            cur.execute("DELETE FROM master_password_hints WHERE email=%s", (email,))
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Hints deleted successfully."})
    except Exception as e:
        print(f"[delete_hints] {e}")
        return jsonify({"error": "Internal server error."}), 500


# DELETE SINGLE VAULT ENTRY (DELETE)
@app.route('/vault/entry', methods=['DELETE'])
@token_required
def delete_vault_entry(email):
    data = request.get_json(silent=True) or {}
    mp   = data.get("masterPassword", "")
    idx  = data.get("index")
    if not mp: return jsonify({"error": "masterPassword is required."}), 400
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT id, encrypted_password, vault_salt FROM vaults "
                "WHERE email=%s ORDER BY id", (email,)
            )
            rows = cur.fetchall()
            ok, err = _validator.entry_index(idx, len(rows))
            if not ok: return jsonify({"error": err}), 400
            target = rows[int(idx)]
            try:
                decrypt_password(derive_key(mp, target["vault_salt"]),
                                 target["encrypted_password"])
            except Exception:
                return jsonify({"error": "Invalid master password."}), 400
            cur.execute("DELETE FROM vaults WHERE id=%s", (target["id"],))
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Entry deleted successfully."})
    except Exception as e:
        print(f"[delete_vault_entry] {e}")
        return jsonify({"error": "Internal server error."}), 500


# DELETE SINGLE VAULT ENTRY (POST) - fallback for clients that drop DELETE bodies
@app.route('/vault/entry/delete', methods=['POST'])
@token_required
def delete_vault_entry_post(email):
    data = request.get_json(silent=True) or {}
    mp   = data.get("masterPassword", "")
    idx  = data.get("index")
    if not mp: return jsonify({"error": "masterPassword is required."}), 400
    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            cur.execute("SELECT salt FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            if not cur.fetchone(): return jsonify({"error": "User not found."}), 401
            cur.execute(
                "SELECT id, encrypted_password, vault_salt FROM vaults "
                "WHERE email=%s ORDER BY id", (email,)
            )
            rows = cur.fetchall()
            ok, err = _validator.entry_index(idx, len(rows))
            if not ok: return jsonify({"error": err}), 400
            target = rows[int(idx)]
            try:
                decrypt_password(derive_key(mp, target["vault_salt"]),
                                 target["encrypted_password"])
            except Exception:
                return jsonify({"error": "Invalid master password."}), 400
            cur.execute("DELETE FROM vaults WHERE id=%s", (target["id"],))
            conn.commit()
        finally:
            cur.close(); conn.close()
        return jsonify({"message": "Entry deleted successfully."})
    except Exception as e:
        print(f"[delete_vault_entry_post] {e}")
        return jsonify({"error": "Internal server error."}), 500


#  DELETE ACCOUNT 
@app.route('/account', methods=['DELETE'])
@token_required
def delete_account(email):
    """
    Permanently delete the user's account and ALL associated data:
      - vault entries
      - memory hints
      - user record
    Requires both login password AND master password for double confirmation.
    ON DELETE CASCADE on the FK handles vault + hints automatically.
    """
    data         = request.get_json(silent=True) or {}
    login_pw     = data.get("password", "")
    master_pw    = data.get("masterPassword", "")

    if not login_pw:  return jsonify({"error": "Login password is required."}), 400
    if not master_pw: return jsonify({"error": "Master password is required."}), 400

    try:
        conn = get_db()
        cur  = conn.cursor(dictionary=True)
        try:
            # Step 1: verify login password
            cur.execute("SELECT * FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            user = cur.fetchone()
            if not user: return jsonify({"error": "User not found."}), 404

            if not secrets.compare_digest(
                hash_login_password(login_pw, user["salt"]),
                user["password_hash"]
            ):
                return jsonify({"error": "Incorrect login password."}), 401

            # Step 2: verify master password against vault (if vault exists)
            cur.execute(
                "SELECT encrypted_password, vault_salt FROM vaults "
                "WHERE email=%s LIMIT 1", (email,)
            )
            sample = cur.fetchone()
            if sample:
                try:
                    decrypt_password(derive_key(master_pw, sample["vault_salt"]),
                                     sample["encrypted_password"])
                except Exception:
                    return jsonify({"error": "Incorrect master password."}), 401

            # Step 3: delete user — CASCADE removes vault + hints automatically
            cur.execute("DELETE FROM users WHERE LOWER(email)=LOWER(%s)", (email,))
            conn.commit()
        finally:
            cur.close(); conn.close()

        return jsonify({"message": "Account permanently deleted. We're sorry to see you go."})
    except Exception as e:
        print(f"[delete_account] {e}")
        return jsonify({"error": "Internal server error."}), 500

# MAIN
if __name__ == '__main__':
    app.run(debug=False)
