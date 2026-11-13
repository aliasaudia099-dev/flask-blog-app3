import sys
sys.path.insert(0, '.')
from app import app
print('Mobile routes:')
for r in app.url_map.iter_rules():
    if 'mobile' in r.rule:
        print(f'  {r.rule} -> {r.endpoint}')