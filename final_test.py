import sys
sys.path.insert(0, '.')
from app import app

with app.test_client() as client:
    # Test GET /mobile/login
    response = client.get('/mobile/login')
    print('GET /mobile/login status:', response.status_code)
    print('Contains 500:', b'500' in response.data if response.data else False)
    print('Contains Internal Server Error:', b'Internal Server Error' in response.data if response.data else False)
    print('Contains traceback:', b'Traceback' in response.data if response.data else False)
    
    # Test POST /mobile/login
    response = client.post('/mobile/login', data={'username': 'admin', 'password': 'admin'})
    print('POST /mobile/login status:', response.status_code)
    print('POST Contains 500:', b'500' in response.data if response.data else False)