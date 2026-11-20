import hashlib


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    hasher = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)

    return hasher.hexdigest()
    import hashlib


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    hasher = hashlib.sha256()

    with open(path, "rb") as file:
        while chunk := file.read(4096):
            hasher.update(chunk)

    return hasher.hexdigest()