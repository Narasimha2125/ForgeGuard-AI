# Rule-specific recommendations, remediation diffs, and documentation links
RECOMMENDATION_DATABASE = {
    "SEC-AWS-KEY-001": {
        "title": "Migrate AWS Credentials to Secrets Manager / Environment Variables",
        "plain_explanation": "An AWS Access Key ID was discovered written directly into your code. Anyone who views the repository can use this key to access your cloud resources.",
        "technical_explanation": "Static credentials in version control can be scraped by automated scanners within seconds of being pushed to remote servers. AWS IAM best practice requires rotating credentials and using IAM Roles, AWS Secrets Manager, or ephemeral tokens.",
        "proposed_diff": """- AWS_KEY = "AKIAEXAMPLEKEY123456"
+ import os
+ AWS_KEY = os.environ.get("AWS_ACCESS_KEY_ID")""",
        "doc_links": "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"
    },
    "SEC-GH-TOKEN-001": {
        "title": "Revoke and Rotate Hardcoded GitHub Token",
        "plain_explanation": "A GitHub personal access token is stored in plain text inside this file.",
        "technical_explanation": "Personal Access Tokens grant scoped or administrative authority over GitHub repositories, packages, and workflows. Hardcoding tokens violates the principle of least privilege.",
        "proposed_diff": """- GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
+ import os
+ GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")""",
        "doc_links": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
    },
    "SEC-SQL-INJECT-001": {
        "title": "Use Parameterized Queries or ORM Binding",
        "plain_explanation": "SQL statements are built using direct string concatenation with variables, allowing malicious inputs to hijack database commands.",
        "technical_explanation": "Direct string interpolation permits attackers to inject SQL syntax fragments (e.g. ' OR 1=1 --), bypassing authentication checks and dumping table contents (CWE-89).",
        "proposed_diff": """- cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
+ cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))""",
        "doc_links": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    "SEC-CMD-INJECT-001": {
        "title": "Avoid shell=True in Subprocess Execution",
        "plain_explanation": "The system shell is invoked to run a process. An attacker could append commands with semicolon (;) or pipe (|) operators.",
        "technical_explanation": "Passing shell=True routes execution through cmd.exe or /bin/sh. Untrusted strings can chain arbitrary commands (CWE-78).",
        "proposed_diff": """- subprocess.run(f"ping -c 1 {host}", shell=True)
+ subprocess.run(["ping", "-c", "1", host], shell=False, check=True)""",
        "doc_links": "https://owasp.org/www-community/attacks/Command_Injection"
    },
    "SEC-EVAL-EXEC-001": {
        "title": "Replace Dynamic Code Execution (eval/exec)",
        "plain_explanation": "eval() executes Python code directly from a string, which can let an attacker execute arbitrary Python commands.",
        "technical_explanation": "Evaluating dynamic strings bypasses type safety and scope isolation, granting access to internal builtins, globals, and system libraries (CWE-95).",
        "proposed_diff": """- result = eval(user_expression)
+ import ast
+ result = ast.literal_eval(user_expression)""",
        "doc_links": "https://docs.python.org/3/library/ast.html#ast.literal_eval"
    },
    "SEC-DESERIAL-001": {
        "title": "Safe Serialization Instead of Pickle",
        "plain_explanation": "Unpickling untrusted data can execute arbitrary system code.",
        "technical_explanation": "Pickle serialization format encodes Python callable objects. The __reduce__ magic method can trigger subprocesses upon unpickling (CWE-502).",
        "proposed_diff": """- data = pickle.loads(raw_bytes)
+ import json
+ data = json.loads(raw_bytes.decode('utf-8'))""",
        "doc_links": "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"
    },
    "PY-HIGH-COMPLEXITY": {
        "title": "Refactor High Cyclomatic Complexity",
        "plain_explanation": "This function contains too many decision paths (if/else/loops), making it hard to understand and test.",
        "technical_explanation": "High cyclomatic complexity increases cognitive load and correlates directly with high defect densities. Each branch doubles the path space.",
        "proposed_diff": """# Break monolithic logic into discrete single-responsibility helper functions
def handle_edge_case(data):
    ...
def execute_main_flow(data):
    ...""",
        "doc_links": "https://radon.readthedocs.io/en/latest/intro.html#cyclomatic-complexity"
    },
    "PY-SILENT-EXCEPTION": {
        "title": "Log or Handle Suppressed Exceptions",
        "plain_explanation": "An exception handler catches errors and ignores them with 'pass'. This hides bugs and makes troubleshooting very difficult.",
        "technical_explanation": "Swallowing exceptions blindly discards tracebacks, state information, and diagnostic messages, propagating corrupt state to downstream components.",
        "proposed_diff": """- except Exception:
-     pass
+ except Exception as exc:
+     logger.warning("Operation failed: %s", exc, exc_info=True)""",
        "doc_links": "https://peps.python.org/pep-0008/#programming-recommendations"
    }
}


def recommend_for_finding(finding):
    rule_id = getattr(finding, "rule_id", "")
    known = RECOMMENDATION_DATABASE.get(rule_id)
    if known:
        return {
            "title": known["title"],
            "plain_explanation": known["plain_explanation"],
            "technical_explanation": known["technical_explanation"],
            "proposed_diff": known["proposed_diff"],
            "doc_links": known["doc_links"],
            "priority": getattr(finding, "severity", "medium")
        }

    # Deterministic fallback based on category and title
    cat = getattr(finding, "category", "code_quality")
    title = getattr(finding, "title", "Issue Detected")
    rec = getattr(finding, "recommendation", "Review code and apply refactoring.")
    fix = getattr(finding, "suggested_fix", "# Refactor to comply with standards.")
    tech = getattr(finding, "technical_explanation", "Identified via static analysis rules.")
    why = getattr(finding, "why_it_matters", "Adhering to clean architecture reduces regression frequency.")

    return {
        "title": f"Remediate: {title}",
        "plain_explanation": f"{title}. {rec}",
        "technical_explanation": tech,
        "proposed_diff": fix,
        "doc_links": "https://cwe.mitre.org/" if cat == "security" else "https://peps.python.org/pep-0008/",
        "priority": getattr(finding, "severity", "medium")
    }
