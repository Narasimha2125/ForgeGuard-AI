import re
from pathlib import Path
from app.engines.code_analyzer import extract_code_snippet

def mask_secret(value: str) -> str:
    """Mask sensitive detected secret values to prevent exposure in logs and UI."""
    if not value or len(value) < 6:
        return "********"
    if len(value) <= 12:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


# Pattern list for Security Analyzer:
# (regex, rule_id, severity, confidence, title, tech_exp, why_matters, recommendation, suggested_fix, is_secret)
SECURITY_PATTERNS = [
    # 1. AWS Credentials
    (
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "SEC-AWS-KEY-001",
        "critical",
        "high",
        "Hardcoded AWS Access Key Detected",
        "An active AWS IAM Access Key ID was detected in source code.",
        "Compromised AWS keys allow unauthorized access to cloud infrastructure, data theft, and resource hijacking.",
        "Revoke the key immediately in AWS IAM console and switch to AWS Secrets Manager or environment variables.",
        "os.getenv('AWS_ACCESS_KEY_ID')",
        True
    ),
    # 2. GitHub Personal Access Token
    (
        r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}|github_pat_[a-zA-Z0-9_]{82}",
        "SEC-GH-TOKEN-001",
        "critical",
        "high",
        "Exposed GitHub Personal Access Token",
        "A GitHub authentication token is hardcoded in source files.",
        "Allows full read/write access to code repositories, organization assets, and CI/CD pipelines.",
        "Revoke this token immediately on GitHub Settings and inject it via environment variables or CI secrets.",
        "os.getenv('GITHUB_TOKEN')",
        True
    ),
    # 3. Private RSA/EC Keys
    (
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "SEC-PRIV-KEY-001",
        "critical",
        "high",
        "Exposed Asymmetric Private Key",
        "An unencrypted private cryptographic key header was found directly in the repository.",
        "Grants attackers the ability to decrypt TLS sessions, sign malicious assertions, or access remote SSH servers.",
        "Rotate the keypair, add the key file to .gitignore, and store secrets in a dedicated vault.",
        "# Store private keys in /etc/ssl/private/ or AWS Secrets Manager with restricted permissions",
        False
    ),
    # 4. Slack Bot/User Token
    (
        r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "SEC-SLACK-TOKEN-001",
        "high",
        "high",
        "Hardcoded Slack API Token",
        "A Slack OAuth API token was detected in source code.",
        "Permits attackers to read internal channel conversations, impersonate team members, and extract proprietary data.",
        "Revoke the token in the Slack Developer Portal and store it in environment variables.",
        "os.getenv('SLACK_BOT_TOKEN')",
        True
    ),
    # 5. Stripe Secret Key
    (
        r"(?:sk|rk)_live_[0-9a-zA-Z]{24,34}",
        "SEC-STRIPE-KEY-001",
        "critical",
        "high",
        "Exposed Stripe Live API Key",
        "A production Stripe live secret or restricted key is hardcoded.",
        "Allows unauthorized adversaries to execute refunds, capture customer charges, and export customer financial data.",
        "Roll the Stripe secret key in Stripe Dashboard and use environment variables.",
        "stripe.api_key = os.getenv('STRIPE_SECRET_KEY')",
        True
    ),
    # 6. Hardcoded Passwords in assignments
    (
        r"(?:password|passwd|pwd|secret_key|db_password|api_secret)\s*=\s*['\"][a-zA-Z0-9_@#!$%^&*]{8,}['\"]",
        "SEC-HARDCODED-PASS-001",
        "high",
        "medium",
        "Hardcoded Password or Secret Assignment",
        "Sensitive credential assigned directly to a static variable.",
        "Static credentials in code repositories are permanently tracked in git history and easily exposed.",
        "Load credentials at runtime from environment variables or a configuration vault.",
        "password = os.environ.get('DATABASE_PASSWORD')",
        True
    ),
    # 7. SQL Injection patterns
    (
        r"(?:execute|raw|cursor\.execute)\s*\(\s*(?:f['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*\{|['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*%s.*%|\w+\s*\+\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE))",
        "SEC-SQL-INJECT-001",
        "critical",
        "high",
        "Potential SQL Injection via Dynamic Query Construction",
        "Dynamic query string formatting or concatenation with runtime variables detected in SQL execution call.",
        "Allows attackers to manipulate query logic, bypass authentication, exfiltrate the entire database, or modify data.",
        "Use parameterized queries with placeholders (%s or :param) or an ORM like SQLAlchemy.",
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        False
    ),
    # 8. Command Injection
    (
        r"(?:subprocess\.(?:call|run|Popen)|os\.system|os\.popen)\s*\([^)]*shell\s*=\s*True",
        "SEC-CMD-INJECT-001",
        "critical",
        "high",
        "Command Injection via shell=True Subprocess Execution",
        "Subprocess invocation specifies shell=True, executing commands through the system shell interpreter.",
        "If untrusted inputs reach this command, arbitrary system shell commands can be executed with application privileges.",
        "Pass arguments as a sequence of strings with shell=False (default). Avoid string concatenation.",
        "subprocess.run(['ls', '-la', directory], shell=False, check=True)",
        False
    ),
    # 9. Dangerous eval() and exec()
    (
        r"\b(?:eval|exec)\s*\([^)]*\)",
        "SEC-EVAL-EXEC-001",
        "high",
        "high",
        "Use of Dynamic Code Execution (eval/exec)",
        "eval() or exec() executes dynamically constructed strings as Python runtime instructions.",
        "Arbitrary code execution vulnerability if any portion of the evaluated string contains untrusted data.",
        "Replace eval/exec with ast.literal_eval, standard JSON parsing, or safe dictionary mappings.",
        "import ast\nsafe_data = ast.literal_eval(untrusted_string)",
        False
    ),
    # 10. Insecure Deserialization (Pickle / Unsafe YAML)
    (
        r"(?:pickle\.loads?|_pickle\.loads?|yaml\.load\([^)]*(?!Loader=SafeLoader)[^)]*\))",
        "SEC-DESERIAL-001",
        "high",
        "high",
        "Insecure Deserialization (Pickle or Unsafe YAML)",
        "Pickle deserialization or yaml.load() without SafeLoader can construct arbitrary Python objects.",
        "Allows Remote Code Execution (RCE) via crafted payloads using __reduce__ or YAML tags.",
        "Use json or yaml.safe_load() instead of pickle for untrusted network payloads.",
        "yaml.safe_load(data)",
        False
    ),
    # 11. Weak Cryptography (MD5 / SHA1)
    (
        r"hashlib\.(?:md5|sha1)\s*\(",
        "SEC-WEAK-CRYPTO-001",
        "medium",
        "high",
        "Use of Cryptographically Broken Hash Algorithm (MD5 / SHA1)",
        "MD5 and SHA-1 have known collision vulnerabilities and are broken for security verification.",
        "Attackers can generate collision attacks to spoof digital signatures or crack passwords with rainbow tables.",
        "Use SHA-256 / SHA-3 for hashing, or Argon2 / bcrypt / pbkdf2_hmac for password hashing.",
        "hashlib.sha256(data).hexdigest()",
        False
    ),
    # 12. Insecure Debug Configuration in production
    (
        r"(?:DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)",
        "SEC-DEBUG-ENABLED-001",
        "medium",
        "high",
        "Debug Mode Explicitly Enabled in Code",
        "The application has debug mode explicitly set to True in source code.",
        "Debug mode enables interactive tracebacks and debug consoles (e.g., Werkzeug PIN debugger) allowing RCE.",
        "Ensure debug mode is conditionally controlled via environment variables and set to False in production.",
        "DEBUG = os.getenv('FLASK_DEBUG', '0') == '1'",
        False
    ),
    # 13. Insecure SSL Verification Disabled
    (
        r"verify\s*=\s*False",
        "SEC-SSL-DISABLED-001",
        "high",
        "high",
        "TLS/SSL Certificate Verification Disabled (verify=False)",
        "HTTP client calls specify verify=False, ignoring TLS certificate validation.",
        "Allows Man-in-the-Middle (MITM) attackers on local networks or proxies to intercept and tamper with traffic.",
        "Remove verify=False and supply trusted CA certificates bundle if internal certificates are required.",
        "requests.get(url, verify=True)",
        False
    ),
    # 14. Unsanitized File Upload handling
    (
        r"(?:\.save\s*\([^)]*filename\b|\.save\s*\([^)]*file\.filename\b)",
        "SEC-UNSAFE-UPLOAD-001",
        "high",
        "medium",
        "Potential Unrestricted File Upload / Path Traversal",
        "Saving user uploaded files directly with user-supplied filename without sanitization.",
        "Allows directory traversal attacks (e.g. filename='../../etc/passwd') or executable file overwrite.",
        "Sanitize filenames using werkzeug.utils.secure_filename and validate extensions against a strict allowlist.",
        "from werkzeug.utils import secure_filename\nsafe_name = secure_filename(file.filename)",
        False
    ),
    # 15. Insecure CORS Configuration
    (
        r"CORS\([^)]*origins\s*=\s*['\"]?\*['\"]?",
        "SEC-INSECURE-CORS-001",
        "medium",
        "medium",
        "Wildcard CORS Configuration (origins='*')",
        "CORS allows wildcard origins, permitting any external web origin to read responses.",
        "Permits malicious third-party websites to extract authenticated user data via cross-origin requests.",
        "Restrict allowed origins to trusted explicit domain names.",
        "CORS(app, origins=['https://app.yourdomain.com'])",
        False
    )
]


def analyze_security_file(path: Path, root_path: Path = None):
    findings = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
    except Exception:
        return []

    for idx, line in enumerate(lines):
        line_num = idx + 1
        for (pattern, rule_id, severity, confidence, title, tech_exp, why_matters, rec, fix, is_secret) in SECURITY_PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                # Mask secret if this pattern detects credentials
                if is_secret:
                    raw_matched = match.group(0)
                    masked = mask_secret(raw_matched)
                    safe_line = line.replace(raw_matched, masked)
                    snippet = extract_code_snippet(lines[:idx] + [safe_line] + lines[idx+1:], line_num)
                    description = f"Detected secret pattern: {masked}"
                else:
                    snippet = extract_code_snippet(lines, line_num)
                    description = f"Detected security pattern: {line.strip()[:100]}"

                col = match.start() + 1
                findings.append({
                    "rule_id": rule_id,
                    "category": "security",
                    "severity": severity,
                    "confidence": confidence,
                    "line_number": line_num,
                    "column_number": col,
                    "code_snippet": snippet,
                    "title": title,
                    "description": description,
                    "technical_explanation": tech_exp,
                    "why_it_matters": why_matters,
                    "recommendation": rec,
                    "suggested_fix": fix,
                    "detection_tool": "ForgeGuard Security Engine"
                })

    return findings
