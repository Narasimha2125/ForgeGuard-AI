import io
import zipfile
import requests
from flask import current_app
from extensions import db
from app.models.integration import Integration
from app.models.project import Project
from app.services.repository_service import safe_extract_archive

GITHUB_API_BASE = "https://api.github.com"

def get_github_integration(user_id: int):
    return Integration.query.filter_by(user_id=user_id, provider="github", is_active=True).first()

def verify_and_save_github_token(user_id: int, token: str):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    res = requests.get(f"{GITHUB_API_BASE}/user", headers=headers, timeout=5)
    if res.status_code != 200:
        raise ValueError("Invalid GitHub Personal Access Token or network issue.")
    user_data = res.json()
    account_name = user_data.get("login", "")

    integration = Integration.query.filter_by(user_id=user_id, provider="github").first()
    if not integration:
        integration = Integration(user_id=user_id, provider="github")
        db.session.add(integration)

    integration.account_name = account_name
    integration.access_token = token
    integration.is_active = True
    db.session.commit()
    return integration

def fetch_user_github_repositories(token: str):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    res = requests.get(f"{GITHUB_API_BASE}/user/repos?per_page=50&sort=updated", headers=headers, timeout=5)
    if res.status_code != 200:
        return []
    repos = res.json()
    return [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "description": r.get("description") or "",
            "language": r.get("language") or "Other",
            "stars": r.get("stargazers_count", 0),
            "forks": r.get("forks_count", 0),
            "default_branch": r.get("default_branch", "main"),
            "private": r.get("private", False),
            "html_url": r.get("html_url")
        }
        for r in repos if isinstance(r, dict)
    ]

def import_github_repository(user_id: int, repo_full_name: str, branch: str = None):
    integration = get_github_integration(user_id)
    if not integration or not integration.access_token:
        raise ValueError("GitHub integration is not connected. Add your Personal Access Token in Settings or Integrations.")

    token = integration.access_token
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Fetch repo details first
    repo_res = requests.get(f"{GITHUB_API_BASE}/repos/{repo_full_name}", headers=headers, timeout=5)
    if repo_res.status_code != 200:
        raise ValueError(f"Could not fetch repository '{repo_full_name}' from GitHub.")
    repo_info = repo_res.json()
    default_branch = branch or repo_info.get("default_branch", "main")

    # Download zipball archive
    zip_url = f"{GITHUB_API_BASE}/repos/{repo_full_name}/zipball/{default_branch}"
    zip_res = requests.get(zip_url, headers=headers, timeout=30, stream=True)
    if zip_res.status_code != 200:
        raise ValueError(f"Failed to download repository archive from GitHub (Status {zip_res.status_code}).")

    # Create new Project
    project = Project(
        user_id=user_id,
        name=repo_info.get("name", repo_full_name.split("/")[-1]),
        description=f"Imported from GitHub: {repo_full_name}. {repo_info.get('description', '')}",
        language=repo_info.get("language") or "Unknown"
    )
    db.session.add(project)
    db.session.commit()

    # Wrap raw bytes in a file-like storage
    file_bytes = io.BytesIO(zip_res.content)
    file_bytes.filename = f"{project.name}.zip"

    # Save and extract
    storage_root = current_app.config["UPLOAD_FOLDER"]
    target_dir, primary_lang, file_count, total_bytes, _ = safe_extract_archive(
        file_bytes, project.id, storage_root
    )

    project.source_path = target_dir
    project.language = primary_lang
    project.file_count = file_count
    project.total_size_bytes = total_bytes
    db.session.commit()

    return project
