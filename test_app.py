import sys
sys.path.insert(0, '.')
from app import app

with app.test_client() as client:
    # Test GET /mobile/login
    response = client.get('/mobile/login')
    print('GET /mobile/login Status code:', response.status_code)
    print('GET - No 500 error:', b'500' not in response.data)
    
    # Test POST /mobile/login with dummy credentials
    response = client.post('/mobile/login', data={'username': 'admin', 'password': 'admin'})
    print('POST /mobile/login Status code:', response.status_code)
    print('POST - No 500 error:', b'500' not in response.data)
    if hasattr(response, 'location'):
        print('POST - Redirect location:', response.location)