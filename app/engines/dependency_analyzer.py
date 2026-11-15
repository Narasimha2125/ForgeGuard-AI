import json
import re
from pathlib import Path
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Known vulnerability database fallback (offline high-profile CVEs for rock-solid reliability)
KNOWN_VULNERABILITIES = {
    ("PyPI", "requests"): [
        {
            "affected_versions": ["<2.31.0"],
            "id": "CVE-2023-32681",
            "severity": "medium",
            "summary": "Requests leaks Proxy-Authorization header during cross-origin redirect",
            "fixed_in": "2.31.0"
        }
    ],
    ("PyPI", "urllib3"): [
        {
            "affected_versions": ["<1.26.17", ">=2.0.0,<2.0.6"],
            "id": "CVE-2023-43804",
            "severity": "high",
            "summary": "urllib3 cookie leak across redirects to different origins",
            "fixed_in": "2.0.6"
        },
        {
            "affected_versions": ["<1.26.18", ">=2.0.0,<2.0.7"],
            "id": "CVE-2023-45803",
            "severity": "medium",
            "summary": "Request body not stripped on redirect leading to potential cache poisoning",
            "fixed_in": "2.0.7"
        }
    ],
    ("PyPI", "pyyaml"): [
        {
            "affected_versions": ["<5.4"],
            "id": "CVE-2020-14343",
            "severity": "critical",
            "summary": "Arbitrary code execution through FullLoader in PyYAML",
            "fixed_in": "5.4"
        }
    ],
    ("PyPI", "flask"): [
        {
            "affected_versions": ["<1.0.0"],
            "id": "CVE-2018-1000656",
            "severity": "high",
            "summary": "Improper input handling in Flask json decoding",
            "fixed_in": "1.0.0"
        }
    ],
    ("PyPI", "jinja2"): [
        {
            "affected_versions": ["<3.1.3"],
            "id": "CVE-2024-22195",
            "severity": "medium",
            "summary": "HTML attribute injection vulnerability in xmlattr filter",
            "fixed_in": "3.1.3"
        }
    ],
    ("npm", "lodash"): [
        {
            "affected_versions": ["<4.17.21"],
            "id": "CVE-2021-23337",
            "severity": "high",
            "summary": "Command injection vulnerability in lodash template",
            "fixed_in": "4.17.21"
        },
        {
            "affected_versions": ["<4.17.19"],
            "id": "CVE-2020-8203",
            "severity": "high",
            "summary": "Prototype pollution via zipObjectDeep in lodash",
            "fixed_in": "4.17.19"
        }
    ],
    ("npm", "axios"): [
        {
            "affected_versions": ["<0.21.2"],
            "id": "CVE-2021-3749",
            "severity": "medium",
            "summary": "Regular expression denial of service (ReDoS) in trim method",
            "fixed_in": "0.21.2"
        }
    ],
    ("Maven", "org.apache.logging.log4j:log4j-core"): [
        {
            "affected_versions": ["<2.15.0"],
            "id": "CVE-2021-44228",
            "severity": "critical",
            "summary": "Log4Shell JNDI Remote Code Execution vulnerability in Log4j2",
            "fixed_in": "2.15.0"
        }
    ]
}


def parse_version_tuple(v_str):
    """Simple semver tuple converter for comparison."""
    clean = re.sub(r"[^\d.]", "", v_str.split("-")[0])
    parts = []
    for p in clean.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_version_affected(installed_ver: str, condition: str) -> bool:
    """Check if installed_ver satisfies condition like '<2.31.0' or '>=2.0.0,<2.0.6'."""
    if not installed_ver:
        return False
    inst = parse_version_tuple(installed_ver)
    sub_conds = condition.split(",")
    for sc in sub_conds:
        sc = sc.strip()
        if sc.startswith("<="):
            target = parse_version_tuple(sc[2:])
            if not (inst <= target):
                return False
        elif sc.startswith("<"):
            target = parse_version_tuple(sc[1:])
            if not (inst < target):
                return False
        elif sc.startswith(">="):
            target = parse_version_tuple(sc[2:])
            if not (inst >= target):
                return False
        elif sc.startswith(">"):
            target = parse_version_tuple(sc[1:])
            if not (inst > target):
                return False
        elif sc.startswith("=="):
            target = parse_version_tuple(sc[2:])
            if not (inst == target):
                return False
    return True


def query_osv_api(ecosystem: str, name: str, version: str):
    """Query OSV.dev REST API for vulnerabilities with timeout and error protection."""
    if not REQUESTS_AVAILABLE or not version:
        return []
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": ecosystem}
        }
        res = requests.post(url, json=payload, timeout=2.5)
        if res.status_code == 200:
            data = res.json()
            vulns = []
            for item in data.get("vulns", []):
                vuln_id = item.get("id", "UNKNOWN-VULN")
                summary = item.get("summary") or item.get("details", "")[:120]
                # extract fixed version if available
                fixed = "Latest"
                for affected in item.get("affected", []):
                    for r in affected.get("ranges", []):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed = event["fixed"]
                # Determine severity
                sev = "medium"
                for s in item.get("severity", []):
                    if s.get("type") == "CVSS_V3":
                        score_str = s.get("score", "")
                        if "CRITICAL" in score_str or "/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in score_str:
                            sev = "critical"
                        elif "HIGH" in score_str:
                            sev = "high"
                vulns.append({
                    "id": vuln_id,
                    "summary": summary,
                    "severity": sev,
                    "fixed_in": fixed
                })
            return vulns
    except Exception:
        pass
    return []


def parse_requirements_txt(content: str):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # match name and version
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=|>|<)?\s*([0-9a-zA-Z_\-\.]*)", line)
        if m:
            pkg_name = m.group(1).lower()
            ver = m.group(2) if m.group(2) else ""
            packages.append({"name": pkg_name, "version": ver, "ecosystem": "PyPI", "direct": True})
    return packages


def parse_package_json(content: str):
    packages = []
    try:
        data = json.loads(content)
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        for name, ver in deps.items():
            clean_ver = re.sub(r"[\^~>=<]", "", ver)
            packages.append({"name": name, "version": clean_ver, "ecosystem": "npm", "direct": True})
        for name, ver in dev_deps.items():
            clean_ver = re.sub(r"[\^~>=<]", "", ver)
            packages.append({"name": name, "version": clean_ver, "ecosystem": "npm", "direct": False})
    except Exception:
        pass
    return packages


def parse_package_lock_json(content: str):
    packages = []
    try:
        data = json.loads(content)
        # v2/v3 packages
        if "packages" in data:
            for key, val in data["packages"].items():
                if not key:
                    continue
                name = key.replace("node_modules/", "")
                ver = val.get("version", "")
                packages.append({"name": name, "version": ver, "ecosystem": "npm", "direct": False})
        # v1 dependencies
        elif "dependencies" in data:
            for name, val in data["dependencies"].items():
                ver = val.get("version", "")
                packages.append({"name": name, "version": ver, "ecosystem": "npm", "direct": False})
    except Exception:
        pass
    return packages


def parse_pyproject_toml(content: str):
    packages = []
    # simple regex parser for dependencies in pyproject.toml
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("[") and ("dependencies" in line or "poetry.dependencies" in line):
            in_deps = True
            continue
        elif line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip().strip('"').strip("'").lower()
            ver_part = parts[1].strip().strip('"').strip("'")
            ver_match = re.search(r"[\d\.]+", ver_part)
            ver = ver_match.group(0) if ver_match else ""
            if name and name != "python":
                packages.append({"name": name, "version": ver, "ecosystem": "PyPI", "direct": True})
    return packages


def parse_cargo_toml(content: str):
    packages = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line == "[dependencies]":
            in_deps = True
            continue
        elif line.startswith("[") and in_deps:
            in_deps = False
        if in_deps and "=" in line:
            name, ver_raw = line.split("=", 1)
            name = name.strip()
            ver_match = re.search(r'[\d\.]+', ver_raw)
            ver = ver_match.group(0) if ver_match else ""
            packages.append({"name": name, "version": ver, "ecosystem": "crates.io", "direct": True})
    return packages


def parse_go_mod(content: str):
    packages = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        elif line == ")" and in_require:
            in_require = False
            continue
        elif line.startswith("require "):
            parts = line.split()
            if len(parts) >= 3:
                packages.append({"name": parts[1], "version": parts[2].lstrip("v"), "ecosystem": "Go", "direct": True})
        elif in_require:
            parts = line.split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1].lstrip("v"), "ecosystem": "Go", "direct": True})
    return packages


def analyze_dependency_file(path: Path, root_path: Path = None):
    findings = []
    packages = []
    file_name = path.name.lower()
    
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []

    if file_name == "requirements.txt" or file_name.endswith(".txt"):
        packages = parse_requirements_txt(content)
    elif file_name == "package.json":
        packages = parse_package_json(content)
    elif file_name in ("package-lock.json", "npm-shrinkwrap.json"):
        packages = parse_package_lock_json(content)
    elif file_name == "pyproject.toml":
        packages = parse_pyproject_toml(content)
    elif file_name == "cargo.toml":
        packages = parse_cargo_toml(content)
    elif file_name == "go.mod":
        packages = parse_go_mod(content)

    rel_path = str(path.relative_to(root_path)) if root_path else path.name

    for pkg in packages:
        name = pkg["name"]
        ver = pkg.get("version", "")
        eco = pkg.get("ecosystem", "PyPI")
        
        # 1. Check known local vulnerability catalog
        known_list = KNOWN_VULNERABILITIES.get((eco, name), [])
        matched_vulns = []
        for kv in known_list:
            for aff in kv["affected_versions"]:
                if is_version_affected(ver, aff):
                    matched_vulns.append(kv)
                    break

        # 2. Query OSV.dev if online and not matched locally
        if not matched_vulns and ver and REQUESTS_AVAILABLE:
            osv_results = query_osv_api(eco, name, ver)
            matched_vulns.extend(osv_results)

        for v in matched_vulns:
            vid = v.get("id", "VULN-DEP-001")
            sev = v.get("severity", "medium").lower()
            fixed = v.get("fixed_in", "the latest secure version")
            summary = v.get("summary", f"Vulnerable dependency: {name}=={ver}")
            
            findings.append({
                "rule_id": f"DEP-{vid}",
                "category": "dependency",
                "severity": sev,
                "confidence": "high",
                "line_number": 1,
                "column_number": 1,
                "code_snippet": f"{name}=={ver} (Vulnerable: {vid})",
                "title": f"Vulnerable Dependency: {name} ({vid})",
                "description": f"Package '{name}' version {ver} is affected by {vid}: {summary}",
                "technical_explanation": f"Security vulnerability reported in {eco} registry. Severity: {sev.upper()}. Fixed in: {fixed}.",
                "why_it_matters": "Using libraries with known CVEs permits automated exploits targeting known bugs or supply chain flaws.",
                "recommendation": f"Upgrade '{name}' to version {fixed} or higher.",
                "suggested_fix": f"# Upgrade {name} in {file_name}:\n{name}>={fixed}",
                "detection_tool": "OSV.dev Intelligence & ForgeGuard SCA"
            })

    return findings, packages
