from app import get_db_connection
from werkzeug.security import generate_password_hash

def create_admin():
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password, approved, is_admin) VALUES (?, ?, ?, ?, ?)",
            ("admin", "admin@test.com", generate_password_hash("admin123"), 1, 1)
        )
        conn.commit()
        print("✅ Admin account created successfully!")
        print("Username: admin")
        print("Password: admin123")
    except Exception as e:
        print(f"❌ Error creating admin: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    create_admin()