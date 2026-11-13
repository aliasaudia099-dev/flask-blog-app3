import sys
sys.path.insert(0, '.')
from app import app

with app.test_client() as client:
    # First login
    response = client.post('/login', data={'username': 'admin', 'password': 'admin'}, follow_redirects=False)
    print('Login status:', response.status_code)
    print('Login location:', response.location)
    
    # Now test settings
    response = client.get('/settings', follow_redirects=False)
    print('Settings GET status (logged in):', response.status_code)
    print('Settings GET location:', response.location)
    print('Body contains 500:', b'500' in response.data if response.data else False)