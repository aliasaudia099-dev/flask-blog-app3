import sys
sys.path.insert(0, '.')
from database import Database
db = Database()
ps = db.get_fps_settings()
print("mobile_login_enabled:", ps.get("mobile_login_enabled"))
print("Full settings:", ps)