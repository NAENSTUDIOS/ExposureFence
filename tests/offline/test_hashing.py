from scoring.hashing import sha256_text


def test_hash_consistency():
    a = sha256_text("hello")
    b = sha256_text("hello")

    assert a == b
    from scoring.hashing import sha256_text


def test_hash_consistency():
    hash1 = sha256_text("hello")
    hash2 = sha256_text("hello")

    assert hash1 == hash2