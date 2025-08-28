# user_manager.py
from app import get_db_connection
from werkzeug.security import generate_password_hash


def check_user(username):
    """Check a user's status"""
    conn = get_db_connection()
    user = conn.execute(
        "SELECT username, email, approved, email_verified FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if user:
        print(f"""
        USER STATUS
        -----------
        Username: {user['username']}
        Email: {user['email']}
        Approved: {'✅' if user['approved'] else '❌'}
        Verified: {'✅' if user['email_verified'] else '❌'}
        """)
    else:
        print(f"❌ User '{username}' not found")


def verify_user(username):
    """Mark a user's email as verified"""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET email_verified=1 WHERE username=?",
            (username,))
        conn.commit()
        print(f"✅ {username} email verification FORCED")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        conn.close()


def approve_user(username):
    """Approve a pending user"""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET approved=1 WHERE username=?",
            (username,))
        conn.commit()
        print(f"✅ {username} account APPROVED")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        conn.close()


def reset_password(username, new_password):
    """Reset a user's password"""
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE users SET password=? WHERE username=?",
            (generate_password_hash(new_password), username))
        conn.commit()
        print(f"✅ {username} password reset to: {new_password}")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="User Management Tool")

    parser.add_argument("username", help="Username to manage")
    parser.add_argument("--verify", action="store_true", help="Verify user's email")
    parser.add_argument("--approve", action="store_true", help="Approve user account")
    parser.add_argument("--reset-pw", help="Reset password (provide new password)")
    parser.add_argument("--check", action="store_true", help="Check user status")  # Fixed position

    args = parser.parse_args()

    if args.check:
        check_user(args.username)
    if args.verify:
        verify_user(args.username)
    if args.approve:
        approve_user(args.username)
    if args.reset_pw:
        reset_password(args.username, args.reset_pw)

    if not any([args.check, args.verify, args.approve, args.reset_pw]):
        print("⚠️ No action specified. Use --help for options.")