import zklib

# ZKLib connection via TCP/IP
zk = zklib.ZK('192.168.1.201', port=4370, timeout=5)

print("Connecting...")
connection = zk.connect()
print(f"Connected: {connection}")

if connection:
    # Get attendance
    print("\n--- Getting Attendance ---")
    attendance = zk.get_attendance()
    print(f"Attendance records: {len(attendance)}")
    for r in attendance[:5]:  # Show first 5
        print(f"  ID: {r.id}, Date: {r.date}, Time: {r.timestamp}, Status: {r.status}")
    
    # Get user list
    print("\n--- Getting User List ---")
    users = zk.get_users()
    print(f"Users: {len(users)}")
    for u in users[:5]:  # Show first 5
        print(f"  User ID: {u.uid}, Name: {u.name}, Privilege: {u.privilege}")