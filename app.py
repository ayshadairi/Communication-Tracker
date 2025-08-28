from flask import Flask, render_template, request, redirect, url_for, flash, Response, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from datetime import datetime, timedelta
import sqlite3
import pandas as pd
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pathlib import Path
import click
from flask.cli import with_appcontext
from openpyxl import Workbook
import secrets
import string
from flask_mail import Mail, Message
import os
import re

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me')

# Email configuration for local testing
app.config.update(
    MAIL_SERVER='localhost',
    MAIL_PORT=1025,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=None,
    MAIL_PASSWORD=None,
    MAIL_DEFAULT_SENDER='no-reply@localhost',
    MAIL_SUPPRESS_SEND=False,
    MAIL_DEBUG=True
)
mail = Mail(app)

# Database configuration
DATABASE_PATH = Path(__file__).parent / 'instance' / 'logs.db'
DATABASE_PATH.parent.mkdir(exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

# Initialize Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


class User(UserMixin):
    def __init__(self, id):
        self.id = str(id)

    def get_id(self):
        return str(self.id)

    def is_verified(self):
        conn = get_db_connection()
        user = conn.execute('SELECT email_verified FROM users WHERE id = ?', [self.id]).fetchone()
        conn.close()
        return user['email_verified'] if user else False

    def is_admin(self):
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', [self.id]).fetchone()
        conn.close()
        return user['is_admin'] if user else False

    def is_approved(self):
        conn = get_db_connection()
        user = conn.execute('SELECT approved FROM users WHERE id = ?', [self.id]).fetchone()
        conn.close()
        return user['approved'] if user else False


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL CHECK(length(username) BETWEEN 3 AND 20),
            password TEXT NOT NULL CHECK(length(password) >= 8),
            email TEXT UNIQUE,
            email_verified BOOLEAN DEFAULT FALSE,
            verify_token TEXT,
            reset_token TEXT,
            token_expires DATETIME,
            approved BOOLEAN DEFAULT FALSE,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person_type TEXT NOT NULL CHECK(person_type IN ('Employer', 'Student')),
            name TEXT NOT NULL CHECK(length(name) BETWEEN 2 AND 50),
            date TEXT NOT NULL,
            interaction_type TEXT NOT NULL CHECK(interaction_type IN (
                'Phone Call', 'Email', 'In-Person', 'Meeting')),
            notes TEXT NOT NULL CHECK(length(notes) <= 500),
            issue_type TEXT NOT NULL CHECK(issue_type IN (
                'Just Checking', 'Problem', 'Complaint', 'Request',
                'Feedback', 'Inquiry', 'Technical Issue',
                'Billing/Payment', 'Follow-Up', 'Urgent', 'Other')),
            user_id INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()


@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize the database."""
    init_db()
    click.echo('Initialized the database.')


@click.command('create-admin')
@with_appcontext
def create_admin():
    """Create an admin user."""
    conn = get_db_connection()
    try:
        username = input("Enter admin username: ")
        email = input("Enter admin email: ")
        password = input("Enter admin password: ")

        conn.execute(
            "INSERT INTO users (username, password, email, approved, is_admin) VALUES (?, ?, ?, ?, ?)",
            (username, generate_password_hash(password), email, True, True)
        )
        conn.commit()
        click.echo(f'Admin user {username} created successfully!')
    except sqlite3.IntegrityError:
        click.echo('Error: Username or email already exists')
    finally:
        conn.close()


app.cli.add_command(init_db_command)
app.cli.add_command(create_admin)


def send_verification_email(user_email, token):
    verify_link = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email', recipients=[user_email])
    msg.body = f'''Please click the following link to verify your email:
{verify_link}

If you didn't create an account, please ignore this email.'''
    mail.send(msg)


def send_admin_notification(username, email):
    admin_email = "admin@example.com"  # Change to your admin email
    approve_link = url_for('admin_users', _external=True)
    msg = Message('New User Approval Request', recipients=[admin_email])
    msg.body = f'''New user registration requires approval:
Username: {username}
Email: {email}

Approve this user: {approve_link}'''
    mail.send(msg)


def generate_reset_token():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))


@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin():
        abort(403)

    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, email, approved, is_admin, created_at 
        FROM users 
        ORDER BY approved ASC, created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin_dashboard.html')

@app.route('/admin/approve/<int:user_id>')
@login_required
def approve_user(user_id):
    if not current_user.is_admin():
        abort(403)

    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET approved = TRUE WHERE id = ?', [user_id])

        user = conn.execute('SELECT email FROM users WHERE id = ?', [user_id]).fetchone()
        if user:
            msg = Message('Account Approved', recipients=[user['email']])
            msg.body = 'Your account has been approved. You can now log in.'
            mail.send(msg)

        conn.commit()
        flash('User approved successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error approving user: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/make-admin/<int:user_id>')
@login_required
def make_admin(user_id):
    if not current_user.is_admin():
        abort(403)

    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_admin = TRUE WHERE id = ?', [user_id])
        conn.commit()
        flash('User granted admin privileges', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error updating user: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_users'))


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = escape(request.form.get('username', '').strip())
        email = escape(request.form.get('email', '').strip())
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not EMAIL_REGEX.match(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register'))

        if not 3 <= len(username) <= 20:
            flash('Username must be 3-20 characters', 'error')
            return redirect(url_for('register'))

        if not username.isalnum():
            flash('Username can only contain letters and numbers', 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if not any(c.isdigit() for c in password):
            flash('Password must contain at least 1 number', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            hashed_password = generate_password_hash(password)
            verify_token = generate_reset_token()
            conn.execute(
                "INSERT INTO users (username, password, email, verify_token) VALUES (?, ?, ?, ?)",
                (username, hashed_password, email, verify_token)
            )
            conn.commit()

            send_verification_email(email, verify_token)
            send_admin_notification(username, email)

            flash(
                'Registration successful! Please check your email for verification. Your account will be active after admin approval.',
                'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            flash('Username or email already exists', 'error')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/verify/<token>')
def verify_email(token):
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE verify_token = ?', [token]).fetchone()
        if user:
            conn.execute('UPDATE users SET email_verified = TRUE, verify_token = NULL WHERE id = ?', [user['id']])
            conn.commit()
            flash('Email verified successfully! Waiting for admin approval.', 'success')
        else:
            flash('Invalid or expired verification link', 'error')
    except Exception as e:
        conn.rollback()
        flash('Error verifying email', 'error')
    finally:
        conn.close()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = escape(request.form.get('username', '').strip())
        password = request.form.get('password', '').strip()

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            if not user['email_verified']:
                flash('Please verify your email before logging in', 'error')
                return redirect(url_for('login'))

            if not user['approved']:
                flash('Your account is pending admin approval', 'error')
                return redirect(url_for('login'))

            user_obj = User(str(user['id']))
            login_user(user_obj)
            session['user_id'] = user['id']
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

        flash('Invalid username or password', 'error')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', [current_user.id]).fetchone()
    conn.close()
    return render_template('profile.html', user=user)


@app.route('/change_username', methods=['GET', 'POST'])
@login_required
def change_username():
    if request.method == 'POST':
        new_username = escape(request.form['new_username'].strip())
        password = request.form['password'].strip()

        if not 3 <= len(new_username) <= 20:
            flash('Username must be 3-20 characters', 'error')
            return redirect(url_for('change_username'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', [current_user.id]).fetchone()

        if not check_password_hash(user['password'], password):
            flash('Incorrect password', 'error')
            conn.close()
            return redirect(url_for('change_username'))

        try:
            user_id = current_user.id
            conn.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
            conn.commit()
            conn.close()

            logout_user()
            user_obj = User(user_id)
            login_user(user_obj)

            flash('Username updated successfully!', 'success')
            return redirect(url_for('profile'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
            conn.close()
            return redirect(url_for('change_username'))

    return render_template('change_username.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', [current_user.id]).fetchone()

        if not check_password_hash(user['password'], current_password):
            flash('Current password is incorrect', 'error')
            conn.close()
            return redirect(url_for('change_password'))

        hashed_password = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
        conn.commit()
        conn.close()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', [email]).fetchone()

        if not user:
            flash('If an account exists with this email, a reset link has been sent', 'info')
            conn.close()
            return redirect(url_for('login'))

        try:
            token = generate_reset_token()
            expires = datetime.now() + timedelta(hours=1)

            conn.execute('UPDATE users SET reset_token=?, token_expires=? WHERE id=?', (token, expires, user['id']))
            conn.commit()

            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Reset link: {reset_link} (expires in 1 hour)'
            mail.send(msg)

            flash('Password reset link sent!', 'success')
        except Exception as e:
            flash('Error sending reset email', 'error')
        finally:
            conn.close()

        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE reset_token = ? AND token_expires > ?',
                        [token, datetime.now()]).fetchone()

    if not user:
        conn.close()
        flash('Invalid or expired token', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()

        if len(new_password) < 8:
            flash('Password must be at least 8 characters', 'error')
        elif new_password != confirm:
            flash('Passwords do not match', 'error')
        else:
            conn.execute('''
                UPDATE users 
                SET password=?, reset_token=NULL, token_expires=NULL 
                WHERE id=?
            ''', (generate_password_hash(new_password), user['id']))
            conn.commit()
            conn.close()
            flash('Password updated! Please login.', 'success')
            return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token)


@app.route('/')
@login_required
def index():
    conn = get_db_connection()

    filters = {
        'name': request.args.get('name', ''),
        'person_type': request.args.get('person_type', ''),
        'interaction_type': request.args.get('interaction_type', ''),
        'issue_type': request.args.get('issue_type', ''),
        'date_from': request.args.get('date_from', ''),
        'date_to': request.args.get('date_to', ''),
        'created_by': request.args.get('created_by', '')
    }
    all_users = conn.execute('SELECT username FROM users').fetchall()
    query = '''
        SELECT logs.*, users.username, CAST(logs.user_id AS INTEGER) as user_id_int 
        FROM logs JOIN users ON logs.user_id = users.id
    '''
    params = []

    if filters['name']:
        query += " WHERE logs.name LIKE ?"
        params.append(f"%{filters['name']}%")
    if filters['person_type']:
        query += " WHERE " if not params else " AND "
        query += "logs.person_type = ?"
        params.append(filters['person_type'])
    if filters['interaction_type']:
        query += " WHERE " if not params else " AND "
        query += "logs.interaction_type = ?"
        params.append(filters['interaction_type'])
    if filters['issue_type']:
        query += " WHERE " if not params else " AND "
        query += "logs.issue_type = ?"
        params.append(filters['issue_type'])
    if filters['date_from']:
        query += " WHERE " if not params else " AND "
        query += "logs.date >= ?"
        params.append(filters['date_from'])
    if filters['date_to']:
        query += " WHERE " if not params else " AND "
        query += "logs.date <= ?"
        params.append(filters['date_to'])
    if filters['created_by']:
        query += " WHERE " if not params else " AND "
        query += "logs.created_by = ?"
        params.append(filters['created_by'])

    query += " ORDER BY logs.date DESC"
    logs = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('index.html', logs=logs, filters=filters, all_users=all_users)


@app.route('/student/<student_name>')
@login_required
def student_communications(student_name):
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT logs.*, users.username, CAST(logs.user_id AS INTEGER) as user_id_int
        FROM logs JOIN users ON logs.user_id = users.id 
        WHERE logs.name = ?
        ORDER BY logs.date DESC
    ''', [student_name]).fetchall()
    conn.close()

    return render_template('student_comms.html', logs=logs, student_name=student_name)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_log():
    if request.method == 'POST':
        try:
            person_type = escape(request.form.get('person_type'))
            name = escape(request.form.get('name', '').strip())
            interaction_type = escape(request.form.get('interaction_type'))
            issue_type = escape(request.form.get('issue_type'))
            notes = escape(request.form.get('notes', '').strip())
            date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if not 2 <= len(name) <= 50:
                flash('Name must be 2-50 characters')
                return redirect(url_for('add_log'))

            if len(notes) > 500:
                flash('Notes cannot exceed 500 characters')
                return redirect(url_for('add_log'))

            conn = get_db_connection()
            user = conn.execute("SELECT username FROM users WHERE id = ?", [current_user.id]).fetchone()

            conn.execute('''
                INSERT INTO logs (
                    person_type, name, date, interaction_type, 
                    notes, issue_type, user_id, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (person_type, name, date, interaction_type,
                  notes, issue_type, current_user.id, user['username']))

            conn.commit()
            conn.close()
            flash('Log added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error creating log: {str(e)}', 'error')
            return redirect(url_for('add_log'))

    return render_template('add_log.html')


@app.route('/edit/<int:log_id>', methods=['GET', 'POST'])
@login_required
def edit_log(log_id):
    conn = get_db_connection()
    log = conn.execute('''
        SELECT logs.*, users.username 
        FROM logs JOIN users ON logs.user_id = users.id 
        WHERE logs.id = ?
    ''', [log_id]).fetchone()

    if not log or log['user_id'] != current_user.id:
        conn.close()
        flash("You can only edit your own logs", 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            person_type = escape(request.form.get('person_type'))
            name = escape(request.form.get('name', '').strip())
            interaction_type = escape(request.form.get('interaction_type'))
            issue_type = escape(request.form.get('issue_type'))
            notes = escape(request.form.get('notes', '').strip())

            if not 2 <= len(name) <= 50:
                flash('Name must be 2-50 characters')
                return redirect(url_for('edit_log', log_id=log_id))

            if len(notes) > 500:
                flash('Notes cannot exceed 500 characters')
                return redirect(url_for('edit_log', log_id=log_id))

            conn.execute('''
                UPDATE logs
                SET person_type=?, name=?, interaction_type=?, 
                    notes=?, issue_type=?
                WHERE id=? AND user_id=?
            ''', (person_type, name, interaction_type,
                  notes, issue_type, log_id, current_user.id))

            conn.commit()
            conn.close()
            flash('Log updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error updating log: {str(e)}', 'error')
            return redirect(url_for('edit_log', log_id=log_id))

    conn.close()
    return render_template('edit_log.html', log=dict(log))


@app.route('/delete/<int:log_id>')
@login_required
def delete_log(log_id):
    conn = get_db_connection()
    log = conn.execute("SELECT user_id FROM logs WHERE id = ?", [log_id]).fetchone()

    if log and log['user_id'] == current_user.id:
        conn.execute("DELETE FROM logs WHERE id = ?", [log_id])
        conn.commit()
        flash('Log deleted successfully', 'success')
    else:
        flash("You can only delete your own logs", 'error')

    conn.close()
    return redirect(url_for('index'))


@app.route('/export')
@login_required
def export():
    try:
        conn = get_db_connection()

        filters = {
            'name': request.args.get('name', ''),
            'person_type': request.args.get('person_type', ''),
            'interaction_type': request.args.get('interaction_type', ''),
            'issue_type': request.args.get('issue_type', ''),
            'date_from': request.args.get('date_from', ''),
            'date_to': request.args.get('date_to', ''),
            'created_by': request.args.get('created_by', '')
        }

        query = '''
            SELECT logs.*, users.username 
            FROM logs JOIN users ON logs.user_id = users.id
        '''
        params = []

        if filters['name']:
            query += " WHERE logs.name LIKE ?"
            params.append(f"%{filters['name']}%")
        if filters['person_type']:
            query += " WHERE " if not params else " AND "
            query += "logs.person_type = ?"
            params.append(filters['person_type'])
        if filters['interaction_type']:
            query += " WHERE " if not params else " AND "
            query += "logs.interaction_type = ?"
            params.append(filters['interaction_type'])
        if filters['issue_type']:
            query += " WHERE " if not params else " AND "
            query += "logs.issue_type = ?"
            params.append(filters['issue_type'])
        if filters['date_from']:
            query += " WHERE " if not params else " AND "
            query += "logs.date >= ?"
            params.append(filters['date_from'])
        if filters['date_to']:
            query += " WHERE " if not params else " AND "
            query += "logs.date <= ?"
            params.append(filters['date_to'])
        if filters['created_by']:
            query += " WHERE " if not params else " AND "
            query += "logs.created_by = ?"
            params.append(filters['created_by'])

        query += " ORDER BY logs.date DESC"
        logs = conn.execute(query, params).fetchall()
        column_names = [description[0] for description in conn.execute(query, params).description]
        conn.close()

        wb = Workbook()
        ws = wb.active
        ws.title = "Communication Logs"

        ws.append(column_names)
        for log in logs:
            ws.append([log[col] for col in column_names])

        output = BytesIO()
        wb.save(output)
        output.seek(0)

        return Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment;filename=communication_logs.xlsx"}
        )
    except Exception as e:
        flash(f"Error exporting data: {str(e)}", 'error')
        return redirect(url_for('index'))


@app.route('/admin/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_users'))
    if not current_user.is_admin():
        abort(403)

    conn = get_db_connection()
    try:
        # First delete any logs by this user
        conn.execute('DELETE FROM logs WHERE user_id = ?', (user_id,))
        # Then delete the user
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting user: {str(e)}', 'error')
    finally:
        conn.close()

    return redirect(url_for('admin_users'))


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)