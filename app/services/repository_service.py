import os
import shutil
import zipfile
from pathlib import Path
from flask import current_app
from extensions import db
from app.models.project import Project
from app.models.project_file import ProjectFile

DEFAULT_EXCLUDED = {
    "node_modules", ".git", ".venv", "venv", "__pycache__",
    "dist", "build", "coverage", "vendor", ".idea", ".vscode",
    ".pytest_cache", ".mypy_cache", ".tox", "target", "bin", "obj"
}

EXTENSION_LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".hpp": "C++ Header",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".sql": "SQL",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".md": "Markdown"
}


def sanitize_exclusion_list(custom_exclusions: str = "") -> set:
    exclusions = set(DEFAULT_EXCLUDED)
    if custom_exclusions:
        for item in custom_exclusions.split(","):
            cleaned = item.strip().lower()
            if cleaned:
                exclusions.add(cleaned)
    return exclusions


def safe_extract_archive(file_storage, project_id: int, storage_root: str, custom_exclusions: str = ""):
    root = Path(storage_root).resolve()
    target_dir = (root / f"project_{project_id}").resolve()
    if target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)
    target_dir.mkdir(parents=True, exist_ok=True)

    archive_temp = (root / f"upload_temp_{project_id}.zip").resolve()
    file_storage.save(archive_temp)

    if not zipfile.is_zipfile(archive_temp):
        if archive_temp.exists():
            archive_temp.unlink()
        raise ValueError("Uploaded file is not a valid ZIP archive or is corrupted.")

    # Limits from config or env
    max_file_size = current_app.config.get("MAX_FILE_EXTRACTION_MB", 100) * 1024 * 1024
    max_total_size = current_app.config.get("MAX_TOTAL_EXTRACTION_MB", 1000) * 1024 * 1024
    max_file_count = current_app.config.get("MAX_ARCHIVE_FILES", 25000)

    excluded_dirs = sanitize_exclusion_list(custom_exclusions)

    total_extracted_bytes = 0
    extracted_file_count = 0

    try:
        with zipfile.ZipFile(archive_temp, "r") as zf:
            infolist = zf.infolist()
            
            # Pre-scan archive check: count and decompression ratio to defend against zip bombs
            uncompressed_sum = sum(info.file_size for info in infolist)
            compressed_sum = sum(info.compress_size for info in infolist) or 1
            if (uncompressed_sum / compressed_sum) > 100 and uncompressed_sum > 100 * 1024 * 1024:
                raise ValueError("ZIP decompression ratio exceeds safe limit (>100:1 archive bomb suspected).")

            for info in infolist:
                # Skip directories
                if info.is_dir():
                    continue

                raw_path = Path(info.filename)
                
                # Check path traversal
                if raw_path.is_absolute() or ".." in raw_path.parts:
                    raise ValueError(f"Unsafe path traversal detected in ZIP archive: {info.filename}")

                # Check if file falls into excluded directory
                lower_parts = {part.lower() for part in raw_path.parts}
                if any(ex in lower_parts for ex in excluded_dirs):
                    continue

                # File size check
                if info.file_size > max_file_size:
                    raise ValueError(f"File '{info.filename}' exceeds per-file limit ({max_file_size // (1024*1024)} MB).")

                total_extracted_bytes += info.file_size
                extracted_file_count += 1

                if total_extracted_bytes > max_total_size:
                    raise ValueError("Extracted repository exceeds maximum extraction storage quota.")

                if extracted_file_count > max_file_count:
                    raise ValueError("Repository contains too many files exceeding maximum extraction allowance.")

                # Target file path inside repository directory
                dest = (target_dir / raw_path).resolve()
                
                # Ensure destination resides strictly inside target directory
                try:
                    dest.relative_to(target_dir)
                except ValueError:
                    raise ValueError(f"Extracted file path escapes sandbox: {info.filename}")

                dest.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(dest, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=64 * 1024)

    except zipfile.BadZipFile:
        raise ValueError("Corrupted ZIP archive file.")
    finally:
        if archive_temp.exists():
            archive_temp.unlink()

    # Index files and calculate language distribution
    file_records, language_breakdown, primary_language = index_repository_files(project_id, target_dir)

    return str(target_dir), primary_language, extracted_file_count, total_extracted_bytes, language_breakdown


def index_repository_files(project_id: int, target_dir: Path):
    """Walks the extracted directory, indexes files in ProjectFile, and calculates language breakdown."""
    # Clear existing file records for this project
    ProjectFile.query.filter_by(project_id=project_id).delete()

    language_counts = {}
    file_records = []

    for path in target_dir.rglob("*"):
        if path.is_file():
            rel = str(path.relative_to(target_dir))
            ext = path.suffix.lower()
            lang = EXTENSION_LANGUAGE_MAP.get(ext, "Other")
            size = path.stat().st_size
            
            # Count lines if text file
            line_count = 0
            if size < 5 * 1024 * 1024:
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        line_count = sum(1 for _ in f)
                except Exception:
                    line_count = 0

            pf = ProjectFile(
                project_id=project_id,
                file_path=str(path),
                relative_path=rel,
                file_name=path.name,
                extension=ext,
                file_size_bytes=size,
                line_count=line_count,
                language=lang,
                is_analyzed=ext in (".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".txt", ".toml", ".yaml", ".yml", ".mod")
            )
            db.session.add(pf)
            file_records.append(pf)

            if lang != "Other":
                language_counts[lang] = language_counts.get(lang, 0) + 1

    db.session.commit()

    primary_language = max(language_counts, key=language_counts.get) if language_counts else "General"
    return file_records, language_counts, primary_language


def get_repository_tree(project_id: int):
    """Constructs a nested file/folder tree for the repository explorer UI."""
    files = ProjectFile.query.filter_by(project_id=project_id).order_by(ProjectFile.relative_path).all()
    tree = {"name": "root", "type": "directory", "children": {}}

    for f in files:
        parts = Path(f.relative_path).parts
        curr = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                # File node
                curr["children"][part] = {
                    "name": part,
                    "type": "file",
                    "path": f.relative_path,
                    "language": f.language,
                    "size": f.file_size_bytes,
                    "lines": f.line_count
                }
            else:
                # Directory node
                if part not in curr["children"]:
                    curr["children"][part] = {
                        "name": part,
                        "type": "directory",
                        "children": {}
                    }
                curr = curr["children"][part]

    def flatten_tree(node):
        if node["type"] == "directory":
            children_list = [flatten_tree(child) for child in node["children"].values()]
            # Sort directories first, then files
            children_list.sort(key=lambda x: (0 if x["type"] == "directory" else 1, x["name"].lower()))
            node["children"] = children_list
        return node

    return flatten_tree(tree)["children"]
