import requests

# Vulnerability: Exposed static API credential
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE12345678901234567890"

def fetch_data():
    headers = {"Authorization": f"Bearer {AWS_SECRET_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)