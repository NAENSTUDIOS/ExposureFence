import os
from scoring.hashing import sha256_file

FIXTURE_HASHES = {
    "mock_data/s3_buckets.json": "7adc573cb9aab105f12df1e275c627b140bba41ea0b3a2b893daf7ffd6ba220f",
    "mock_data/security_groups.json": "6914f6651dd488df5c0444e5d46fb8df2de2142daf5a346f41c1edfa0eb5fa96"
}


def get_fixture_hash(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized in FIXTURE_HASHES:
        return FIXTURE_HASHES[normalized]
    basename_key = f"mock_data/{os.path.basename(normalized)}"
    return FIXTURE_HASHES.get(basename_key)


def verify_fixture_integrity(path: str) -> bool:
    expected = get_fixture_hash(path)
    if not expected:
        return False
    if not os.path.exists(path):
        return False
    return sha256_file(path) == expected
