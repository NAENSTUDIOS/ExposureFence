import json


def read_mock_s3():
    with open("mock_data/s3_buckets.json") as f:
        return json.load(f)


def read_mock_security_groups():
    with open("mock_data/security_groups.json") as f:
        return json.load(f)