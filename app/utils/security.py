from werkzeug.security import safe_join

def safe_storage_path(root, relative_path):
    return safe_join(root, relative_path)
