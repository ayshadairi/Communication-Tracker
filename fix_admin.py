from app import get_db_connection

def fix_admin():
    conn = get_db_connection()
    try:
        conn.execute("UPDATE users SET email_verified=1 WHERE username='admin'")
        conn.commit()
        print("✅ Success! Admin account is now email-verified.")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_admin()