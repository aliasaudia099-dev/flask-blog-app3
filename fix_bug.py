import re

# Read the file
with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find and replace the incorrect function call
# The bug is: emp = db.get_employee_by_face()
# Should be: emp = db.get_employee_by_code(username) or db.get_employee_by_national_id(username)

# Actually, looking at line 1339, it already has the correct code.
# Let me check what's on line 1342

# Let's search for the specific pattern
pattern = r"emp = db\.get_employee_by_face\(\)"
replacement = "emp = db.get_employee_by_code(username) or db.get_employee_by_national_id(username)"

# Check if pattern exists
if re.search(pattern, content):
    new_content = re.sub(pattern, replacement, content)
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("Fixed!")
else:
    print("Pattern not found, checking alternative...")
    # Try alternative pattern
    pattern2 = r"get_employee_by_face\(\)"
    if re.search(pattern2, content):
        new_content = re.sub(pattern2, replacement, content)
        with open('app.py', 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("Fixed with alternative!")
    else:
        print("No matching pattern found")