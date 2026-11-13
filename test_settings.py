import sys
sys.path.insert(0, '.')
from app import app

# Print all rules with their endpoints
for r in app.url_map.iter_rules():
    if r.endpoint and ('login' in r.endpoint.lower() or 'setting' in r.endpoint.lower() or 'mobile' in r.endpoint.lower()):
        print(f"{r.rule:30} -> {r.endpoint}")