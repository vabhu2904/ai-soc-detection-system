import hashlib


def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file."""
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print("[ERROR] File not found.")
        return None
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return None