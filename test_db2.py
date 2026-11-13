import sys
sys.path.insert(0, '.')
from database import Database
try:
    db = Database()
    print('Database connected successfully')
except Exception as e:
    print('Error:', e)