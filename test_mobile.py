import sys
sys.path.insert(0, '.')
from app import app

with app.test_client() as client:
    # Test POST /mobile/login
    response = client.post('/mobile/login', data={'username': 'test', 'password': 'test'})
    print('POST /mobile/login status:', response.status_code)
    print('Body contains 500:', b'500' in response.data if response.data else False)