import sys
sys.path.insert(0, '.')
from database import Database
db = Database()
result = db.get_employee_by_code('TEST001')
print('get_employee_by_code result:', result)