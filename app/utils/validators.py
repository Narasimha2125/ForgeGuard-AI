def valid_project_name(name):
    return bool(name and 1 <= len(name.strip()) <= 120)
