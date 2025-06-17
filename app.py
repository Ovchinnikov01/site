from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime,timedelta
import pytz
import random
import sqlite3  
import os
import math

app = Flask(__name__)
app.secret_key = "secret key"
DATABASE = 'database.db'

app.config['UPLOAD_FOLDER'] = 'static/survey_images'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def truncate_words(text, length):
    if not text:
        return ""
    words = text.split()
    if len(words) > length:
        return ' '.join(words[:length]) + '...'
    return text

app.jinja_env.filters['truncate_words'] = truncate_words

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def create_tables():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        email TEXT UNIQUE NOT NULL,
        profile_picture TEXT,
        role TEXT DEFAULT 'user',
        organization TEXT,
        job_title TEXT,
        registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS surveys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        rating REAL,
        image TEXT,
        user TEXT,
        type TEXT,
        form_type TEXT,
        job_title TEXT,
        job_company TEXT,
        job_location TEXT,
        job_description TEXT,
        job_requirements TEXT,
        job_salary TEXT,
        event_name TEXT,
        event_date TEXT,
        event_time TEXT,
        event_location TEXT,
        event_description TEXT,
        event_organizer TEXT,
        contest_name TEXT,
        contest_description TEXT,
        contest_start_date TEXT,
        contest_end_date TEXT,
        contest_requirements TEXT,
        contest_prizes TEXT,
        last_activity_time DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS survey_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        survey_id INTEGER NOT NULL,
        question_text TEXT NOT NULL,
        FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS responses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        survey_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        response_text TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES survey_questions(id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    text TEXT NOT NULL,
    survey_id INTEGER NOT NULL,
    parent_comment_id INTEGER DEFAULT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_comment_id) REFERENCES comments(id) ON DELETE CASCADE
)
''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    survey_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    rating REAL DEFAULT 0.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE,
    UNIQUE (user_id, survey_id)
);
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        link TEXT,
        is_read INTEGER DEFAULT 0,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    image TEXT,
    user TEXT,
    type TEXT,
    form_type TEXT,
    job_title TEXT,
    job_company TEXT,
    job_location TEXT,
    registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        survey_id INTEGER NOT NULL,
        rating REAL NOT NULL CHECK(rating >= 1 AND rating <= 5),
        FOREIGN KEY (survey_id) REFERENCES surveys(id) ON DELETE CASCADE
    );
    ''')

    db.commit()
    db.close()

def get_users_with_status():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, role, created_at FROM users")
    users = cursor.fetchall()
    db.close()
    return users

def get_latest_surveys_with_comments(limit=10, min_comments=5):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT s.*, COUNT(c.id) AS comment_count
        FROM surveys s
        LEFT JOIN comments c ON s.id = c.survey_id
        WHERE s.type = 'survey'
        GROUP BY s.id
        HAVING comment_count >= ?
        ORDER BY s.last_activity_time DESC
        LIMIT ?
    """, (min_comments, limit))
    surveys = cursor.fetchall()
    db.close()
    return surveys

def get_comment_count(survey_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM comments WHERE survey_id = ?", (survey_id,))
    count = cursor.fetchone()[0]
    db.close()
    return count

def get_latest_surveys(limit=10):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            s.id,
            s.title,
            s.description,
            s.image AS survey_image,
            s.last_activity_time,
            COALESCE(AVG(r.rating), s.rating, 0) AS survey_rating,
            u.username AS user_name,
            u.profile_picture AS user_avatar,
            COUNT(c.id) AS comment_count
        FROM surveys s 
        LEFT JOIN reviews r ON s.id = r.survey_id 
        LEFT JOIN users u ON s.user = u.username
        LEFT JOIN comments c ON s.id = c.survey_id
        WHERE s.type = 'survey' 
        GROUP BY s.id
        ORDER BY s.last_activity_time DESC 
        LIMIT ?""", (limit,))
    column_names = [column[0] for column in cursor.description]
    surveys = [dict(zip(column_names, row)) for row in cursor.fetchall()]
    db.close()
    moscow_tz = pytz.timezone('Europe/Moscow')
    for survey in surveys:
        if survey['last_activity_time']:
            if isinstance(survey['last_activity_time'], str):
                utc_time = datetime.strptime(survey['last_activity_time'], '%Y-%m-%d %H:%M:%S')
                utc_time = pytz.utc.localize(utc_time)
            else:
                utc_time = survey['last_activity_time'].replace(tzinfo=pytz.utc)
            survey['moscow_time'] = utc_time.astimezone(moscow_tz).strftime('%d.%m.%Y %H:%M')
        else:
            survey['moscow_time'] = 'Неизвестно'
    return surveys

def get_top_rated_surveys(limit=6, min_rating=3.8):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT s.id, s.title, s.description, s.image, s.user,
               s.last_activity_time, s.rating, COUNT(c.id) AS comment_count
        FROM surveys s
        LEFT JOIN comments c ON s.id = c.survey_id
        WHERE s.type = 'survey' AND s.rating BETWEEN ? AND ?
        GROUP BY s.id
        ORDER BY s.rating DESC
        LIMIT ?
    """, (min_rating, 5.0, limit))

    columns = [col[0] for col in cursor.description]
    results = []
    for row in cursor.fetchall():
        results.append(dict(zip(columns, row)))
    db.close()
    return results

def get_top_commented_surveys(limit=6):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT s.*, COUNT(c.id) AS comment_count
        FROM surveys s
        LEFT JOIN comments c ON s.id = c.survey_id
        GROUP BY s.id
        ORDER BY comment_count DESC
        LIMIT ?
    """, (limit,))
    surveys = cursor.fetchall()
    db.close()
    return surveys

def convert_to_moscow_time(utc_dt):
    """
    Convert UTC datetime to Moscow timezone.
    :param utc_dt: A datetime object in UTC.
    :return: A datetime object in Moscow timezone, or None if input is None.
    """
    if utc_dt is None:
        return None
    if isinstance(utc_dt, str):
        utc_dt = datetime.strptime(utc_dt, '%Y-%m-%d %H:%M:%S')
        utc_dt = pytz.utc.localize(utc_dt)
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=pytz.utc)
    moscow_tz = pytz.timezone('Europe/Moscow')
    return utc_dt.astimezone(moscow_tz)

def format_registration_date(date):
    """
    Format registration date to 'day month year'.
    :param date: A datetime object representing the registration date.
    :return: A formatted date string or "Неизвестно" if input is None.
    """
    if date is None:
        return "Неизвестно"
    if not isinstance(date, datetime):
        raise ValueError("Date must be a datetime object")
    return date.strftime('%d %B %Y')

def format_activity_date(date):
    """
    Format activity date to 'today', 'yesterday', or 'X days ago'.
    :param date: A datetime object representing the activity date.
    :return: A formatted string or "Неизвестно" if input is None.
    """
    if date is None:
        return "Неизвестно"
    if not isinstance(date, datetime):
        raise ValueError("Date must be a datetime object")
    now = datetime.now(pytz.timezone('Europe/Moscow'))
    delta = now.date() - date.date()
    if delta.days == 0:
        return "Сегодня"
    elif delta.days == 1:
        return "Вчера"
    else:
        return f"{delta.days} дней назад"
    
def get_replies(comment_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT c.id, c.user, c.text, c.survey_id, c.parent_comment_id, c.timestamp,
               u.username, u.profile_picture, s.type as survey_type
        FROM comments c
        LEFT JOIN users u ON c.user = u.username
        LEFT JOIN surveys s ON c.survey_id = s.id
        WHERE c.parent_comment_id = ?
        ORDER BY c.timestamp ASC
    """, (comment_id,))
    columns = [column[0] for column in cursor.description]
    replies = [dict(zip(columns, row)) for row in cursor.fetchall()]
    db.close()
    return replies
   
@app.template_filter('truncatewords')
def truncatewords(s, num):
    """Возвращает первые num слов строки s."""
    words = s.split()
    return ' '.join(words[:num]) + ('...' if len(words) > num else '')

def login_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            print("login_required called")
            if 'logged_in' not in session or not session['logged_in']:
                return redirect(url_for('login'))
            if role is not None and session['role'] != role:
                return 'У вас нет прав доступа.', 403
            return func(*args, **kwargs)
        return wrapper
    return decorator

def create_notification(user_id, notification_type, text, link=None):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO notifications (user_id, type, message, link) VALUES (?, ?, ?, ?)",
        (user_id, notification_type, text, link)
    )
    db.commit()
    db.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']
        organization = request.form.get('organization') if role == 'employer' else None
        job_title = request.form.get('job_title') if role == 'employer' else None
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, password, email, role, organization, job_title)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (username, hashed_password, email, role, organization, job_title))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Пользователь с таким именем или электронной почтой уже существует')
        finally:
            db.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_username = 'admin'
        admin_password = 'admin1234'
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()
        if username == admin_username and password == admin_password:
            session['logged_in'] = True
            session['username'] = admin_username
            session['role'] = 'admin'
            return redirect(url_for('admin_panel'))
        if user and check_password_hash(user[2], password):
            session['logged_in'] = True
            session['username'] = user[1]
            session['role'] = user[5]
            session['user_id'] = user[0]
            return redirect(url_for('profile'))
        else:
            return 'Неверный логин или пароль.'
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        flash('Пожалуйста, авторизуйтесь для доступа к профилю.', 'warning')
        return redirect(url_for('login'))
    username = session['username']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    cursor.execute("SELECT * FROM surveys WHERE user = ? AND type = 'survey' ORDER BY last_activity_time DESC", (username,))
    surveys = cursor.fetchall()
    cursor.execute("SELECT * FROM surveys WHERE user = ? AND type = 'form'", (username,))
    forms = cursor.fetchall()
    db.close()
    return render_template('profile.html', user=user,surveys=surveys,forms=forms,get_comment_count=get_comment_count,truncate_words=truncate_words)

@app.route('/user/<username>')
@login_required()
def user_profile(username):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, email, registration_date, last_activity_time FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        return "Пользователь не найден", 404
    cursor.execute("SELECT * FROM surveys WHERE user = ? AND type = 'survey' ORDER BY last_activity_time DESC", (username,))
    user_surveys = cursor.fetchall()
    cursor.execute("SELECT * FROM surveys WHERE user = ? AND type = 'form'", (username,))
    user_forms = cursor.fetchall()
    cursor.execute("SELECT COUNT(*) FROM surveys WHERE user = ? AND type = 'survey'", (username,))
    total_surveys = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM surveys WHERE user = ? AND type = 'form'", (username,))
    total_forms = cursor.fetchone()[0]
    registration_date = user[3]
    last_activity_time = convert_to_moscow_time(user[4])
    formatted_registration_date = format_registration_date(datetime.strptime(registration_date, '%Y-%m-%d %H:%M:%S'))
    formatted_last_activity_time = format_activity_date(last_activity_time)
    db.close()
    return render_template('user_profile.html',user=user,user_surveys=user_surveys,user_forms=user_forms,total_surveys=total_surveys,total_forms=total_forms,
                           registration_date=formatted_registration_date,last_activity_time=formatted_last_activity_time,truncate_words=truncate_words)

@app.route('/delete_survey/<int:survey_id>', methods=['POST'])
def delete_survey(survey_id):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("DELETE FROM responses WHERE survey_id = ?", (survey_id,))
        cursor.execute("DELETE FROM surveys WHERE id = ?", (survey_id,))
        db.commit()
        flash('Опрос успешно удалён!', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Ошибка: {str(e)}', 'danger')
    return redirect(url_for('profile'))

@app.route('/delete_form/<int:form_id>', methods=['POST'])
def delete_form(form_id):
    if 'username' not in session:
        flash('Пожалуйста, авторизуйтесь для удаления формы.', 'warning')
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM surveys WHERE id = ? AND user = ?", (form_id, session['username']))
        db.commit()
        flash('Форма успешно удалена.', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Ошибка при удалении формы: {e}', 'error')
    finally:
        db.close()
    return redirect(url_for('profile'))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required()
def edit_profile():
    username = session['username']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    db.close()
    if user:
        if request.method == 'POST':
            new_email = request.form['email']
            new_password = request.form['password']
            profile_picture = request.files.get('profile_picture')
            db = get_db()
            cursor = db.cursor()
            try:
                cursor.execute("UPDATE users SET email=? WHERE username=?", (new_email, username))
                if new_password:
                    cursor.execute("UPDATE users SET password=? WHERE username=?", (generate_password_hash(new_password), username))
                if profile_picture and profile_picture.filename:
                    filename = secure_filename(profile_picture.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    profile_picture.save(file_path)
                    cursor.execute("UPDATE users SET profile_picture=? WHERE username=?", (filename, username))
                db.commit()
                flash('Изменения сохранены успешно!', 'success')
                return redirect(url_for('profile'))
            except sqlite3.IntegrityError:
                flash('Ошибка при обновлении данных. Возможно, почта уже используется.', 'error')
            finally:
                db.close()
        return render_template('edit_profile.html', user=user)
    else:
        return redirect(url_for('login'))
    
@app.route('/edit_survey/<int:survey_id>', methods=['GET', 'POST'])
@login_required()
def edit_survey(survey_id):
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image = request.files.get('image')
        content_type = request.form.get('content_type')
        form_type = request.form.get('form_type', '')
        try:
            image_path = None
            if image and image.filename:
                original_filename = secure_filename(image.filename)
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
                image.save(upload_path)
                image_path = '/static/survey_images/' + original_filename
            cursor.execute("""
                UPDATE surveys 
                SET title = ?, description = ?, image = ?, type = ?, form_type = ?, last_activity_time = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (title, description, image_path, content_type, form_type, survey_id))
            db.commit()
            flash('Опрос успешно обновлен!', 'success')
            return redirect(url_for('survey', survey_id=survey_id))
        except Exception as e:
            flash(f'Ошибка при обновлении опроса: {e}', 'error')
            db.rollback()
        finally:
            db.close()
    cursor.execute("SELECT * FROM surveys WHERE id = ?", (survey_id,))
    survey = cursor.fetchone()
    if not survey:
        return "Опрос не найден", 404
    return render_template('edit_survey.html', survey=survey)

@app.route('/edit_form/<int:form_id>', methods=['GET', 'POST'])
@login_required()
def edit_form(form_id):
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        try:
            cursor.execute("""
                UPDATE surveys 
                SET title = ?, description = ?, last_activity_time = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (title, description, form_id))
            db.commit()
            flash('Анкета успешно обновлена!', 'success')
            return redirect(url_for('form', form_id=form_id))
        except Exception as e:
            flash(f'Ошибка при обновлении анкеты: {e}', 'error')
            db.rollback()
        finally:
            db.close()
    cursor.execute("SELECT * FROM surveys WHERE id = ? AND type = 'form'", (form_id,))
    form = cursor.fetchone()
    if not form:
        return "Анкета не найдена", 404
    return render_template('edit_form.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login'))

@app.route('/')
def index():
    db = get_db()
    cursor = db.cursor()
    title_filter = request.args.get('title')
    rating_filter = request.args.get('rating')
    creation_date_filter = request.args.get('creation_date')
    sort_order = request.args.get('sort')
    query = """
        SELECT 
            s.id, 
            s.title, 
            s.description, 
            s.image AS survey_image, 
            s.last_activity_time,
            COALESCE(AVG(r.rating), s.rating, 0) AS survey_rating,
            u.username AS user_name, 
            u.profile_picture AS user_avatar,
            COUNT(c.id) AS comment_count
        FROM surveys s 
        LEFT JOIN users u ON s.user = u.username
        LEFT JOIN reviews r ON s.id = r.survey_id
        LEFT JOIN comments c ON s.id = c.survey_id
        WHERE s.type = 'survey'
    """
    params = []
    if title_filter:
        query += " AND s.title LIKE ?"
        params.append(f"%{title_filter}%")
    if creation_date_filter:
        query += " AND DATE(s.registration_date) = ?"
        params.append(creation_date_filter)
    query += " GROUP BY s.id"
    
    if rating_filter == 'high':
        query += " HAVING COALESCE(AVG(r.rating), s.rating, 0) > ?"
        params.append(3.8) 
    elif rating_filter == 'low':
        query += " HAVING COALESCE(AVG(r.rating), s.rating, 0) < ?"
        params.append(3.8)
        
    if sort_order == 'asc':
        query += " ORDER BY s.title ASC"
    elif sort_order == 'desc':
        query += " ORDER BY s.title DESC"
    else:
        query += " ORDER BY s.last_activity_time DESC"
    query += " LIMIT 10"
    cursor.execute(query, params)
    moscow_tz = pytz.timezone('Europe/Moscow')
    last_reviews = []
    for row in cursor.fetchall():
        review = dict(zip([column[0] for column in cursor.description], row))
        if review['last_activity_time']:
            if isinstance(review['last_activity_time'], str):
                utc_time = datetime.strptime(review['last_activity_time'], '%Y-%m-%d %H:%M:%S')
                utc_time = pytz.utc.localize(utc_time)
            else:
                utc_time = review['last_activity_time'].replace(tzinfo=pytz.utc)
            review['moscow_time'] = utc_time.astimezone(moscow_tz).strftime('%d.%m.%Y %H:%M')
        else:
            review['moscow_time'] = 'Неизвестно'
        review['survey_rating'] = float(review['survey_rating']) if review['survey_rating'] is not None else 0.0
        last_reviews.append(review)
    actual_surveys = get_latest_surveys_with_comments(limit=6)
    top_surveys = get_top_rated_surveys(limit=6)
    my_surveys = []
    if 'username' in session:
        username = session['username']
        cursor.execute("SELECT profile_picture FROM users WHERE username = ?", (username,))
        cursor.execute("SELECT * FROM surveys WHERE user = ?", (username,))
        my_surveys = cursor.fetchall()
    db.close()
    return render_template('index.html',actual_surveys=actual_surveys,get_comment_count=get_comment_count,my_surveys=my_surveys,last_reviews=last_reviews,top_surveys=top_surveys,truncate_words=truncate_words)

@app.route('/create_survey', methods=['GET', 'POST'])
@login_required()
def create_survey():
    if session.get('role') == 'admin':
        flash('Администраторам запрещено создавать опросы и анкеты', 'error')
        return redirect(url_for('admin_panel'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'preview':
            return preview_survey()
        content_type = request.form.get('content_type')
        form_type = request.form.get('form_type', None)
        title = request.form['title']
        description = request.form['description']
        image = request.files.get('image')
        job_title = request.form.get('job_title', '')
        job_company = request.form.get('job_company', '')
        job_location = request.form.get('job_location', '')
        job_description = request.form.get('job_description', '')
        job_requirements = request.form.get('job_requirements', '')
        job_salary = request.form.get('job_salary', '')
        event_name = request.form.get('event_name', '')
        event_date = request.form.get('event_date', '')
        event_time = request.form.get('event_time', '')
        event_location = request.form.get('event_location', '')
        event_description = request.form.get('event_description', '')
        event_organizer = request.form.get('event_organizer', '')
        contest_name = request.form.get('contest_name', '')
        contest_description = request.form.get('contest_description', '')
        contest_start_date = request.form.get('contest_start_date', '')
        contest_end_date = request.form.get('contest_end_date', '')
        contest_requirements = request.form.get('contest_requirements', '')
        contest_prizes = request.form.get('contest_prizes', '')
        db = get_db()
        cursor = db.cursor()        
        try:
            image_path = None
            if image and image.filename:
                original_filename = secure_filename(image.filename)
                upload_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
                image.save(upload_path)
                image_path = '/static/survey_images/' + original_filename
            cursor.execute(
                """
                INSERT INTO surveys (
                    title, description, image, user, type, form_type,
                    job_title, job_company, job_location, job_description, job_requirements, job_salary,
                    event_name, event_date, event_time, event_location, event_description, event_organizer,
                    contest_name, contest_description, contest_start_date, contest_end_date, contest_requirements, contest_prizes,
                    last_activity_time
                ) VALUES (
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?,
                    CURRENT_TIMESTAMP
                )
                """,
                (
                    title, description, image_path, session['username'], content_type, form_type,
                    job_title, job_company, job_location, job_description, job_requirements, job_salary,
                    event_name, event_date, event_time, event_location, event_description, event_organizer,
                    contest_name, contest_description, contest_start_date, contest_end_date, contest_requirements, contest_prizes
                )
            )
            db.commit()
            return redirect(url_for('profile'))
        except Exception as e:
            db.rollback()
            flash(f'Ошибка при создании анкеты: {e}', 'error')
            return render_template('create_survey.html', error=str(e))
        finally:
            db.close()
    return render_template('create_survey.html')

@app.route('/preview_survey', methods=['POST'])
@login_required(role=None)
def preview_survey():
    title = request.form['title']
    description = request.form['description']
    image = request.files.get('image')
    content_type = request.form.get('content_type')
    form_type = request.form.get('form_type', None)
    additional_data = {}
    image_filename = None
    if image and image.filename:
        original_filename = secure_filename(image.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        image.save(image_path)
        image_filename = original_filename 
    if content_type == 'form':
        if form_type == 'job':
            additional_data = {
                'job_title': request.form.get('job_title'),
                'job_company': request.form.get('job_company'),
                'job_location': request.form.get('job_location'),
                'job_description': request.form.get('job_description'),
                'job_requirements': request.form.get('job_requirements'),
                'job_salary': request.form.get('job_salary'),
            }
        elif form_type == 'event':
            additional_data = {
                'event_name': request.form.get('event_name'),
                'event_date': request.form.get('event_date'),
                'event_time': request.form.get('event_time'),
                'event_location': request.form.get('event_location'),
                'event_description': request.form.get('event_description'),
                'event_organizer': request.form.get('event_organizer'),
            }
        elif form_type == 'contest':
            additional_data = {
                'contest_name': request.form.get('contest_name'),
                'contest_description': request.form.get('contest_description'),
                'contest_start_date': request.form.get('contest_start_date'),
                'contest_end_date': request.form.get('contest_end_date'),
                'contest_requirements': request.form.get('contest_requirements'),
                'contest_prizes': request.form.get('contest_prizes'),
            }
    return render_template('preview_survey.html', title=title, description=description,image=image_filename, content_type=content_type, form_type=form_type, additional_data=additional_data)

@app.route('/survey/<int:survey_id>', methods=['GET', 'POST'])
@login_required()
def survey(survey_id):
    db = get_db()
    cursor = db.cursor() 
    try:
        cursor.execute("SELECT * FROM surveys WHERE id = ?", (survey_id,))
        survey = cursor.fetchone()
        if not survey:
            return "Опрос не найден", 404 
        cursor.execute("SELECT * FROM survey_questions WHERE survey_id = ?", (survey_id,))
        questions = cursor.fetchall()
        all_options = {}
        for question in questions:
            cursor.execute("SELECT * FROM options WHERE question_id = ?", (question[0],))
            options = cursor.fetchall()
            all_options[question[0]] = options
        cursor.execute("""
            SELECT 
                c.id, c.user, c.text, c.survey_id, c.parent_comment_id, c.timestamp,
                u.username, u.profile_picture
            FROM comments c 
            LEFT JOIN users u ON c.user = u.username 
            WHERE c.survey_id = ? AND c.parent_comment_id IS NULL
            ORDER BY c.timestamp DESC
        """, (survey_id,))
        columns = [column[0] for column in cursor.description]
        comments = []
        moscow_tz = pytz.timezone('Europe/Moscow')
        for row in cursor.fetchall():
            comment = dict(zip(columns, row))
            if comment['timestamp']:
                if isinstance(comment['timestamp'], str):
                    utc_time = datetime.strptime(comment['timestamp'], '%Y-%m-%d %H:%M:%S')
                    utc_time = pytz.utc.localize(utc_time)
                else:
                    utc_time = comment['timestamp'].replace(tzinfo=pytz.utc)
                comment['moscow_time'] = utc_time.astimezone(moscow_tz).strftime('%d.%m.%Y %H:%M')
            else:
                comment['moscow_time'] = 'Неизвестно'
            comments.append(comment)
        cursor.execute("SELECT AVG(rating), COUNT(*) FROM ratings WHERE survey_id = ?", (survey_id,))
        rating_data = cursor.fetchone()
        avg_rating = round(rating_data[0], 1) if rating_data[0] else 0
        rating_count = rating_data[1]
        cursor.execute("SELECT rating FROM ratings WHERE user = ? AND survey_id = ?", 
                      (session['username'], survey_id))
        user_rating = cursor.fetchone()
        user_rating = user_rating[0] if user_rating else None
        if request.method == 'POST':
            if 'text' in request.form:
                text = request.form['text']
                user = session['username']
                cursor.execute("INSERT INTO comments (user, text, survey_id) VALUES (?, ?, ?)", 
                             (user, text, survey_id))
                db.commit()
                cursor.execute("SELECT user FROM surveys WHERE id = ?", (survey_id,))
                survey_owner_username = cursor.fetchone()[0]
                cursor.execute("SELECT id FROM users WHERE username = ?", (survey_owner_username,))
                survey_owner_id = cursor.fetchone()[0]
                create_notification(
                    survey_owner_id,
                    'comment',
                    f'Новый комментарий от {user}!',
                    url_for('survey', survey_id=survey_id)
                )
                return redirect(url_for('survey', survey_id=survey_id))
            elif 'rating' in request.form:
                rating = float(request.form['rating'])
                if user_rating is not None:
                    cursor.execute("""
                        UPDATE ratings SET rating = ? 
                        WHERE user = ? AND survey_id = ?
                    """, (rating, session['username'], survey_id))
                else:
                    cursor.execute("""
                        INSERT INTO ratings (user, survey_id, rating)
                        VALUES (?, ?, ?)
                    """, (session['username'], survey_id, rating))
                db.commit()
                cursor.execute("SELECT AVG(rating) FROM ratings WHERE survey_id = ?", (survey_id,))
                avg_rating = cursor.fetchone()[0] or 0
                avg_rating = round(avg_rating, 1)
                cursor.execute("UPDATE surveys SET rating = ? WHERE id = ?", 
                             (avg_rating, survey_id))
                db.commit()
                cursor.execute("SELECT user FROM surveys WHERE id = ?", (survey_id,))
                survey_owner_username = cursor.fetchone()[0]
                cursor.execute("SELECT id FROM users WHERE username = ?", (survey_owner_username,))
                survey_owner_id = cursor.fetchone()[0]
                create_notification(
                    survey_owner_id,
                    'rating',
                    'Новый рейтинг для вашего опроса!',
                    url_for('survey', survey_id=survey_id)
                )
                return redirect(url_for('survey', survey_id=survey_id))
        return render_template('survey.html', survey=survey, questions=questions, all_options=all_options, comments=comments, 
                               avg_rating=avg_rating,rating_count=rating_count,user_rating=user_rating,get_replies=get_replies)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash("Ошибка при работе с базой данных", "error") 
        return redirect(url_for('survey', survey_id=survey_id))
    finally:
        db.close()

@app.route('/comments/<int:survey_id>', methods=['GET', 'POST'])
@login_required()
def comments(survey_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM surveys WHERE id = ?", (survey_id,))
    survey = cursor.fetchone()
    if not survey:
        return "Опрос не найден", 404
    if request.method == 'POST':
        text = request.form['text']
        user = session['username']
        cursor.execute("INSERT INTO comments (user, text, survey_id) VALUES (?, ?, ?)", (user, text, survey_id))
        db.commit()
        db.close()
        return redirect(url_for('survey', survey_id=survey_id))
    cursor.execute("SELECT c.*, u.profile_picture FROM comments c LEFT JOIN users u ON c.user = u.username WHERE survey_id = ?", (survey_id,))
    comments = cursor.fetchall()
    return render_template('comments.html', survey=survey, comments=comments)

@app.route('/reply_to_comment/<int:comment_id>', methods=['POST'])
@login_required()
def reply_to_comment(comment_id):
    text = request.form['reply_text']
    user = session['username']
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            SELECT c.survey_id, s.type 
            FROM comments c
            JOIN surveys s ON c.survey_id = s.id
            WHERE c.id = ?
        """, (comment_id,))
        result = cursor.fetchone()
        if not result:
            flash('Комментарий не найден', 'error')
            return redirect(url_for('index'))
        
        survey_id, survey_type = result
        cursor.execute("""
            INSERT INTO comments (user, text, survey_id, parent_comment_id)
            VALUES (?, ?, ?, ?)
        """, (user, text, survey_id, comment_id))
        db.commit()
        cursor.execute("SELECT user FROM comments WHERE id = ?", (comment_id,))
        comment_owner = cursor.fetchone()[0]
        cursor.execute("SELECT id FROM users WHERE username = ?", (comment_owner,))
        user_id = cursor.fetchone()[0]
        create_notification(
            user_id,
            'reply',
            f'Новый ответ на ваш комментарий от {user}!',
            url_for('form', form_id=survey_id) if survey_type == 'form' else url_for('survey', survey_id=survey_id)
        )
        flash('Ответ успешно добавлен', 'success')
        if survey_type == 'form':
            return redirect(url_for('form', form_id=survey_id))
        else:
            return redirect(url_for('survey', survey_id=survey_id))
            
    except Exception as e:
        db.rollback()
        flash(f'Ошибка при добавлении ответа: {e}', 'error')
        return redirect(url_for('index'))
    finally:
        db.close()

@app.route('/survey/<int:survey_id>/review', methods=['GET', 'POST'])
@login_required()
def create_review(survey_id):
    if request.method == 'POST':
        text = request.form['text']
        rating = float(request.form['rating'])
        db = get_db()
        cursor = db.cursor()
        cursor.execute("INSERT INTO reviews (user_id, survey_id, text, rating) VALUES (?, ?, ?, ?)",
                       (session['user_id'], survey_id, text, rating))
        db.commit()
        db.close()
        return redirect(url_for('survey', survey_id=survey_id))
    return render_template('create_review.html', survey_id=survey_id)

@app.route('/api/my-surveys')
@login_required()
def api_my_surveys():
    db = get_db()
    cursor = db.cursor()
    username = session['username']
    cursor.execute("SELECT id, title FROM surveys WHERE user = ?", (username,))
    my_surveys = cursor.fetchall()
    db.close()
    surveys_list = []
    for survey in my_surveys:
        survey_id, title = survey
        comment_count = get_comment_count(survey_id)
        surveys_list.append({
            'id': survey_id,
            'title': title,
            'comment_count': comment_count,
            'url': url_for('survey', survey_id=survey_id)
        })
    return jsonify(surveys_list)

PER_PAGE = 6
@app.route('/all_surveys')
@login_required()
def all_surveys():
    db = get_db()
    cursor = db.cursor()
    page = request.args.get('page', 1, type=int)
    per_page = 9
    cursor.execute("SELECT COUNT(*) FROM surveys WHERE type = 'survey'")
    total_surveys = cursor.fetchone()[0]
    total_pages = (total_surveys + per_page - 1) // per_page
    offset = (page - 1) * per_page
    cursor.execute("""
        SELECT 
            s.id,
            s.title,
            s.description,
            s.image,
            COALESCE(AVG(r.rating), s.rating, 0) AS average_rating,
            COUNT(c.id) AS comment_count,
            s.last_activity_time
        FROM surveys s
        LEFT JOIN ratings r ON s.id = r.survey_id
        LEFT JOIN comments c ON s.id = c.survey_id
        WHERE s.type = 'survey'
        GROUP BY s.id
        ORDER BY s.last_activity_time DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))
    column_names = [column[0] for column in cursor.description]
    surveys = [dict(zip(column_names, row)) for row in cursor.fetchall()]
    db.close()
    return render_template('all_surveys.html', surveys=surveys, page=page,total_pages=total_pages, truncate_words=truncate_words, get_comment_count=get_comment_count)

@app.route('/all_forms/')
@app.route('/all_forms/<int:page>')
def all_forms(page=1):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM surveys WHERE type = 'form'")
    total_forms = cursor.fetchone()[0]
    total_pages = math.ceil(total_forms / PER_PAGE)
    offset = (page - 1) * PER_PAGE
    cursor.execute("SELECT * FROM surveys WHERE type = 'form' LIMIT ? OFFSET ?", (PER_PAGE, offset))
    forms = cursor.fetchall()
    db.close()
    return render_template('all_forms.html', forms=forms, page=page, total_pages=total_pages, truncate_words=truncate_words)

@app.route('/form/<int:form_id>', methods=['GET', 'POST'])
@login_required()
def form(form_id):
    db = get_db()
    cursor = db.cursor()
    try:
        if request.method == 'POST':
            text = request.form['text']
            user = session['username']
            cursor.execute("INSERT INTO comments (user, text, survey_id) VALUES (?, ?, ?)", (user, text, form_id))
            db.commit()
            return redirect(url_for('form', form_id=form_id))
        cursor.execute("""
            SELECT c.id, c.user, c.text, c.survey_id, c.parent_comment_id, c.timestamp,
                   u.username, u.profile_picture
            FROM comments c
            LEFT JOIN users u ON c.user = u.username
            WHERE c.survey_id = ?
            ORDER BY c.timestamp DESC
        """, (form_id,))
        columns = [column[0] for column in cursor.description]
        comments = []
        moscow_tz = pytz.timezone('Europe/Moscow')
        for row in cursor.fetchall():
            comment = dict(zip(columns, row))
            if comment['timestamp']:
                if isinstance(comment['timestamp'], str):
                    utc_time = datetime.strptime(comment['timestamp'], '%Y-%m-%d %H:%M:%S')
                    utc_time = pytz.utc.localize(utc_time)
                else:
                    utc_time = comment['timestamp'].replace(tzinfo=pytz.utc)
                comment['moscow_time'] = utc_time.astimezone(moscow_tz).strftime('%d.%m.%Y %H:%M')
            else:
                comment['moscow_time'] = 'Неизвестно'
            comments.append(comment)
        cursor.execute("SELECT * FROM surveys WHERE id = ? AND type = 'form'", (form_id,))
        form = cursor.fetchone()
        if not form:
            return "Анкета не найдена", 404
        form = dict(zip([column[0] for column in cursor.description], form))
        form_type = form['form_type']
        additional_data = {}
        if form_type == 'job':
            additional_data['job_title'] = form['job_title']
            additional_data['job_company'] = form['job_company']
            additional_data['job_location'] = form['job_location']
            additional_data['job_description'] = form['job_description']
            additional_data['job_requirements'] = form['job_requirements']
            additional_data['job_salary'] = form['job_salary']
        elif form_type == 'event':
            additional_data['event_name'] = form['event_name']
            additional_data['event_date'] = form['event_date']
            additional_data['event_time'] = form['event_time']
            additional_data['event_location'] = form['event_location']
            additional_data['event_description'] = form['event_description']
            additional_data['event_organizer'] = form['event_organizer']
        elif form_type == 'contest':
            additional_data['contest_name'] = form['contest_name']
            additional_data['contest_description'] = form['contest_description']
            additional_data['contest_start_date'] = form['contest_start_date']
            additional_data['contest_end_date'] = form['contest_end_date']
            additional_data['contest_requirements'] = form['contest_requirements']
            additional_data['contest_prizes'] = form['contest_prizes']
        cursor.execute("SELECT * FROM survey_questions WHERE survey_id = ?", (form_id,))
        questions = cursor.fetchall()
        return render_template('form.html',form=form, questions=questions, comments=comments, additional_data=additional_data,get_replies=get_replies)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash("Ошибка при работе с базой данных", "error")
        return redirect(url_for('profile'))
    finally:
        db.close()

@app.route('/api/top-surveys')
def api_top_surveys():
    try:
        top_surveys = get_top_rated_surveys(limit=6)
    except Exception as e:
        print(f"Error getting top surveys: {e}")
        return jsonify([]), 500
    surveys_list = []
    for survey in top_surveys:
        survey_data = {
            'id': survey.get('id'),
            'title': truncate_words(survey.get('title', ''), 8),
            'description': truncate_words(survey.get('description', ''), 12),
            'image_url': survey.get('image', '/static/img/no-image.png'),
            'rating': survey.get('rating', 0.0),
            'comment_count': survey.get('comment_count', 0),
            'url': url_for('survey', survey_id=survey.get('id'))
        }
        surveys_list.append(survey_data)

    return jsonify(surveys_list)

@app.route('/search')
def search():
    try:
        query = request.args.get('query', '').strip()
        if not query:
            return jsonify([])
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            SELECT id, title, type, description 
            FROM surveys 
            WHERE title LIKE ? OR description LIKE ?
            ORDER BY last_activity_time DESC
            LIMIT 10
        """, (f'%{query}%', f'%{query}%'))
        results = []
        for row in cursor.fetchall():
            results.append({
                'id': row[0],
                'title': row[1],
                'type': row[2],
                'description': row[3]
            })
        return jsonify(results)
    except Exception as e:
        print(f"Search error: {str(e)}")
        return jsonify({'error': 'Произошла ошибка при поиске'}), 500
    finally:
        db.close()

@app.route('/api/notifications')
@login_required()
def api_notifications():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM notifications WHERE user_id = ? AND is_read = 0", (session['user_id'],))
    notifications = cursor.fetchall()
    db.close()
    return jsonify([{'message': n[3], 'link': n[4]} for n in notifications])

if __name__ == '__main__':
    with app.app_context():
        create_tables()

    users = [
        ('user1', generate_password_hash('user111'), '1', 'user1@gmail.com', 'user', None, None),
        ('user2', generate_password_hash('user222'), '2', 'user2@gmail.com', 'user', None, None),
        ('user3', generate_password_hash('user333'), '3', 'user3@gmail.com', 'user', None, None),
        ('user4', generate_password_hash('user444'), '4', 'user4@gmail.com', 'user', None, None),
        ('user5', generate_password_hash('user555'), '5', 'user5@gmail.com', 'user', None, None)
    ]

    db = get_db()
    cursor = db.cursor()
    for user in users:
        try:
            cursor.execute("""
                INSERT INTO users (username, password, name, email, role, organization, job_title)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, user)
        except sqlite3.IntegrityError:
            print(f"User {user[0]} already exists, skipping.")

    db.commit()
    movie_surveys = [
        (
            'Фильм "Прошлые жизни" (2023) - Первая любовь спустя годы',
            """Достоинства:
            - Потрясающая операторская работа с видами Нью-Йорка и Сеула
            - Уникальный взгляд на тему судьбы и "что если"
            - Игра актёров передаёт тонкие эмоции
            - Отсутствие излишней драматизации
            
            Недостатки:
            - Медленный ритм может утомить
            - Не все диалоги одинаково убедительны
            
            Мой отзыв:
            Этот фильм — как тихий разговор с самим собой поздним вечером. 
            История о корейских друзьях детства, разлучённых эмиграцией, 
            которые встречаются через 20 лет в Нью-Йорке. 
            
            Что особенно цепляет:
            - Как показана культурная идентичность
            - Тонкие намёки на "альтернативные жизни"
            - Сцены молчания говорят больше слов
            
            Для кого: Для тех, кто ценит камерное кино и ностальгию.""",
            'user1',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1489599849927-2ee91cede3ba',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Сериал "Мост" (2011-2018) - Скандинавский нуар',
            """Достоинства:
            - Атмосфера холодного реализма
            - Захватывающий детективный сюжет
            - Незабываемый дуэт главных героев
            
            Недостатки:
            - Слишком мрачная цветовая гамма
            - Некоторые серии растянуты
            
            Мой отзыв:
            Этот датско-шведский сериал начинается с находки трупа 
            ровно на границе двух стран. 
            
            Почему стоит посмотреть:
            - Реалистичные полицейские процедуры
            - Социальные проблемы без прикрас
            - Развитие персонажей через сезоны
            
            Лучшая сцена: Диалоги в машине через границу.""",
            'user2',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1517604931442-7e0c8ed2963c',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Фильм "Довод" (2020) - Игра с временем',
            """Достоинства:
            - Инновационная концепция обращения времени
            - Впечатляющие визуальные эффекты
            - Динамичные экшен-сцены
            
            Недостатки:
            - Сложный для восприятия сюжет
            - Некоторые моменты требуют повторного просмотра
            
            Мой отзыв:
            Кристофер Нолан снова бросает вызов зрителю. 
            Фильм о шпионе, который пытается предотвратить 
            глобальную катастрофу, используя технологию "инверсии времени".
            
            Что впечатлило:
            - Сцена с перевёрнутым автомобилем
            - Звуковое сопровождение
            - Нелинейное повествование""",
            'user3',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1536440136628-849c177e76a1',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Сериал "Чернобыль" (2019) - Хроника катастрофы',
            """Достоинства:
            - Историческая достоверность
            - Атмосфера тревоги и ужаса
            - Великолепная игра актёров
            
            Недостатки:
            - Мрачный и депрессивный
            - Некоторые художественные преувеличения
            
            Мой отзыв:
            Потрясающая реконструкция событий аварии на ЧАЭС. 
            Сериал показывает не только сам взрыв, но и его последствия, 
            как технические, так и человеческие.
            
            Самые сильные моменты:
            - Сцена с ликвидаторами на крыше
            - Судебное заседание
            - Финал с современными кадрами""",
            'user4',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1560169897-fc0cdbdfa4d5',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        )
    ]
    book_surveys = [
        (
            'Книга "Три товарища" Ремарка - Дружба и потеря',
            """Достоинства:
            - Пронзительное описание мужской дружбы
            - Исторический контекст Веймарской республики
            - Философские размышления о жизни
            
            Недостатки:
            - Может показаться слишком пессимистичной
            - Некоторые диалоги старомодны
            
            Мой отзыв:
            Перечитала спустя 10 лет — и как будто другая книга. 
            История трёх ветеранов Первой мировой, пытающихся 
            найти себя в мирной жизни. 
            
            Что осталось со мной:
            - Сцена с розами у санатория
            - Разговоры в гараже
            - Последние строки романа""",
            'user3',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1544947950-fa07a98d237f',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Книга "1984" Джорджа Оруэлла - Антиутопия',
            """Достоинства:
            - Пророческое видение тоталитаризма
            - Глубокие философские вопросы
            - Атмосфера подавления и страха
            
            Недостатки:
            - Мрачная и депрессивная
            - Медленное развитие сюжета
            
            Мой отзыв:
            Роман, который с каждым годом становится всё актуальнее. 
            История Уинстона Смита в мире тотального контроля 
            и манипуляции сознанием.
            
            Ключевые моменты:
            - Концепция "двоемыслия"
            - Любовная линия с Джулией
            - Финал, который невозможно забыть""",
            'user4',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1589998059171-988d887df646',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Книга "Маленькая жизнь" Ханьи Янагихары - История травмы',
            """Достоинства:
            - Глубокое исследование психологии травмы
            - Яркие, запоминающиеся персонажи
            - Эмоциональная интенсивность
            
            Недостатки:
            - Очень тяжелое содержание
            - Длинные описания
            
            Мой отзыв:
            Книга, которая оставляет след в душе. История четырёх друзей 
            в Нью-Йорке, но в центре - Джуд с его страшным прошлым.
            
            Что поражает:
            - Глубина раскрытия характеров
            - Описание дружбы и любви
            - Неожиданные повороты сюжета""",
            'user5',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        )
    ]
    travel_surveys = [
        (
            'Поездка в Исландию - Земля льда и огня',
            """Достоинства:
            - Уникальные пейзажи как с другой планеты
            - Чистейший воздух и вода
            - Дружелюбные местные жители
            
            Недостатки:
            - Очень дорого
            - Переменчивая погода
            
            Мой опыт:
            Путешествовали на авто по кольцевой дороге 10 дней. 
            
            Самые яркие моменты:
            1. Купание в Голубой лагуне при -5°C
            2. Водопад Скоугафосс в лучах заката
            3. Ледниковая лагуна Йёкюльсаурлоун
            
            Совет: Берите термобельё даже летом!""",
            'user4',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1469796466635-455ede028aca',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Отдых в Грузии - Гостеприимный Кавказ',
            """Достоинства:
            - Вкуснейшая кухня и вино
            - Красивая природа и архитектура
            - Низкие цены по сравнению с Европой
            
            Недостатки:
            - Проблемы с инфраструктурой вне туристических мест
            - Языковой барьер в регионах
            
            Мой опыт:
            Маршрут: Тбилиси - Кахетия - Казбеги - Батуми (2 недели).
            
            Что запомнилось:
            - Дегустация вин в Сигнахи
            - Вид на Казбек из церкви Св. Троицы
            - Тбилисские серные бани
            - Пляжи Батуми
            
            Совет: Учите базовые грузинские фразы!""",
            'user5',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1552465011-b4e21bf6e79a',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Поход по Алтаю - Горные приключения',
            """Достоинства:
            - Захватывающие дух пейзажи
            - Чистейшие реки и озёра
            - Возможность отключиться от цивилизации
            
            Недостатки:
            - Сложные маршруты для новичков
            - Переменчивая горная погода
            
            Мой опыт:
            7-дневный треккинг по Чуйскому хребту с ночёвками в палатках.
            
            Самые яркие впечатления:
            - Восхождение на перевал
            - Купание в ледяном озере
            - Ночи у костра под звёздами
            
            Совет: Берите хорошую трекинговую обувь!""",
            'user1',
            'survey',
            'none',
            'https://images.unsplash.com/photo-1588666309990-d68f08e3d4a6',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        )
    ]

    all_surveys = movie_surveys + book_surveys + travel_surveys

    for survey in all_surveys:
        cursor.execute("SELECT * FROM surveys WHERE title = ?", (survey[0],))
        existing_survey = cursor.fetchone()
        
        if existing_survey is None:
            if len(survey) < 24:
                survey = survey + (None,) * (24 - len(survey))
                
            cursor.execute("""
                INSERT INTO surveys (
                    title, description, user, type, form_type, image,
                    job_title, job_company, job_location, job_description, job_requirements, job_salary,
                    event_name, event_date, event_time, event_location, event_description, event_organizer,
                    contest_name, contest_description, contest_start_date, contest_end_date, contest_requirements, contest_prizes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, survey[:24])
            
            survey_id = cursor.lastrowid
            num_comments = random.randint(3, 8)
            for i in range(num_comments):
                cursor.execute("""
                    INSERT INTO comments (user, text, survey_id)
                    VALUES (?, ?, ?)
                """, (f'user{random.randint(1, 5)}', f'Комментарий {i + 1} к "{survey[0]}"', survey_id))
            num_ratings = random.randint(2, 5)
            for i in range(num_ratings):
                user_id = random.randint(1, 5)
                rating = round(random.uniform(3.0, 5.0), 1)
                cursor.execute("SELECT * FROM ratings WHERE user = ? AND survey_id = ?", (f'user{user_id}', survey_id))
                existing_rating = cursor.fetchone()
                if not existing_rating:
                    cursor.execute("""
                        INSERT INTO ratings (user, survey_id, rating)
                        VALUES (?, ?, ?)
                    """, (f'user{user_id}', survey_id, rating))
            
            cursor.execute("SELECT AVG(rating) FROM ratings WHERE survey_id = ?", (survey_id,))
            avg_rating = cursor.fetchone()[0]
            if avg_rating:
                cursor.execute("UPDATE surveys SET rating = ? WHERE id = ?", (round(avg_rating, 1), survey_id))

    basic_forms = [
        (
            'Форма для вакансии Senior Python Developer', 
            'Ищем опытного Python разработчика для работы над высоконагруженными сервисами.', 
            'user1', 
            'form', 
            'job', 
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            'Senior Python Developer', 'TechSolutions Inc.', 'Москва/удаленно',
            'Разработка backend-части веб-приложений. Оптимизация производительности. Участие в проектировании архитектуры.',
            'Опыт работы с Python от 5 лет. Знание Django/Flask. Опыт с PostgreSQL, Redis. Понимание REST, GraphQL.',
            'от 250 000 руб.',
            None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Конференция WebDev 2023', 
            'Крупнейшая конференция по веб-разработке в России.', 
            'user2', 
            'form', 
            'event', 
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None,
            'WebDev Conf 2023', '2023-11-15', '09:00', 'Москва', 
            'Двухдневная конференция с докладами ведущих экспертов. Темы: JavaScript, React, Next.js, GraphQL, микросервисы.',
            'Ассоциация веб-разработчиков',
            None, None, None, None, None
        ),
        (
            'Конкурс стартапов в сфере FinTech', 
            'Грантовый конкурс для финансовых стартапов.', 
            'user3', 
            'form', 
            'contest', 
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None, None, None, None, None, None, None,
            'FinTech Challenge 2023', 'Конкурс для инновационных проектов в финансовой сфере.', 
            '2023-10-01', '2023-12-01', 
            'Проект должен быть на стадии MVP. Команда от 2 человек.',
            'Гранты до 200000 руб. Акселерационная программа.'
        )
    ]
    detailed_job_forms = [
        (
            'Lead UX/UI Designer',
            'Требуется ведущий дизайнер интерфейсов для создания продуктов мирового уровня.',
            'user4',
            'form',
            'job',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            'Lead UX/UI Designer',
            'Digital Innovations Ltd.',
            'Санкт-Петербург',
            'Руководство дизайн-командой. Создание дизайн-систем. Проведение UX-исследований. Взаимодействие с product-менеджерами.',
            'Опыт от 5 лет. Портфолио с кейсами. Знание Figma, Adobe XD. Опыт проведения юзабилити-тестов. Английский B2+.',
            'от 300 000 руб.',
            None, None, None, None, None, None, None, None, None, None, None, None, None
        ),
        (
            'Data Engineer',
            'Ищем инженера данных для построения ETL-процессов и data pipelines.',
            'user5',
            'form',
            'job',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            'Data Engineer',
            'BigData Analytics',
            'Москва/удаленно',
            'Разработка и поддержка ETL-процессов. Оптимизация запросов. Работа с большими объемами данных.',
            'Опыт с Python, SQL. Знание Airflow, Spark. Опыт работы с Hadoop, Kafka. Понимание DWH концепций.',
            'от 280 000 руб.',
            None, None, None, None, None, None, None, None, None, None, None, None, None
        )
    ]
    detailed_event_forms = [
        (
            ' Искусственному интеллекту',
            '48-часовой марафон по созданию AI-решений.',
            'user1',
            'form',
            'event',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None,
            'AI Hackathon 2023',
            '2023-12-10',
            '10:00',
            'Москва',
            'Командное соревнование по разработке AI-решений. Призы для победителей. Менторская поддержка.',
            'AI Community Russia',
            None, None, None, None, None
        ),
        (
            'DevOps Meetup',
            'Ежемесячная встреча DevOps-инженеров.',
            'user2',
            'form',
            'event',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None,
            'DevOps Meetup #15',
            '2023-11-25',
            '19:00',
            'Онлайн (Zoom)',
            'Разбор кейсов по CI/CD, Kubernetes, мониторингу. Доклады от практиков.',
            'DevOps Professionals Club',
            None, None, None, None, None
        )
    ]
    detailed_contest_forms = [
        (
            'Конкурс мобильного дизайна',
            'Соревнование на лучший UI/UX дизайн приложения.',
            'user3',
            'form',
            'contest',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None, None, None, None, None, None, None,
            'Mobile Design Awards 2023',
            'Создайте дизайн мобильного приложения по заданному ТЗ.',
            '2023-11-01',
            '2023-12-01',
            'Предоставить полный набор экранов в Figma. Оригинальность концепции.',
            '1 место - 150 000 руб., публикация в дизайн-сообществах.'
        ),
        (
            'Олимпиада по алгоритмам',
            'Соревнование по решению алгоритмических задач.',
            'user4',
            'form',
            'contest',
            'https://images.unsplash.com/photo-1541462608143-67571c6738dd?ixlib=rb-1.2.1&auto=format&fit=crop&w=500&q=60',
            None, None, None, None, None, None, None, None, None, None, None, None,
            'Algorithm Masters 2023',
            'Индивидуальное соревнование по алгоритмам и структурам данных.',
            '2023-12-05',
            '2023-12-05',
            'Участие для студентов и профессионалов. Языки: Python, Java, C++.',
            'Призы от спонсоров, возможность стажировки.'
        )
    ]
    all_forms = basic_forms + detailed_job_forms + detailed_event_forms + detailed_contest_forms
    for form in all_forms:
        cursor.execute("SELECT * FROM surveys WHERE title = ?", (form[0],))
        existing_form = cursor.fetchone()
        
        if existing_form is None:
            if len(form) < 24:
                form = form + (None,) * (24 - len(form))
            cursor.execute("""
                INSERT INTO surveys (
                    title, description, user, type, form_type, image,
                    job_title, job_company, job_location, job_description, job_requirements, job_salary,
                    event_name, event_date, event_time, event_location, event_description, event_organizer,
                    contest_name, contest_description, contest_start_date, contest_end_date, contest_requirements, contest_prizes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, form[:24])
            form_id = cursor.lastrowid
            num_comments = random.randint(3, 8)
            for i in range(num_comments):
                cursor.execute("""
                    INSERT INTO comments (user, text, survey_id)
                    VALUES (?, ?, ?)
                """, (f'user{random.randint(1, 5)}', f'Комментарий {i + 1} для {form[0]}', form_id))
            num_ratings = random.randint(2, 5)
            for i in range(num_ratings):
                user_id = random.randint(1, 5)
                rating = round(random.uniform(3.0, 5.0), 1)
                cursor.execute("SELECT * FROM ratings WHERE user = ? AND survey_id = ?", (f'user{user_id}', form_id))
                existing_rating = cursor.fetchone()
                if not existing_rating:
                    cursor.execute("""
                        INSERT INTO ratings (user, survey_id, rating)
                        VALUES (?, ?, ?)
                    """, (f'user{user_id}', form_id, rating))
            cursor.execute("SELECT AVG(rating) FROM ratings WHERE survey_id = ?", (form_id,))
            avg_rating = cursor.fetchone()[0]
            if avg_rating:
                cursor.execute("UPDATE surveys SET rating = ? WHERE id = ?", (round(avg_rating, 1), form_id))

    db.commit()
    db.close()

@app.route('/admin_panel')
@login_required(role='admin')
def admin_panel():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, title FROM surveys")
    surveys = cursor.fetchall()
    cursor.execute("SELECT id, title FROM surveys WHERE type = 'form'")
    forms = cursor.fetchall()
    
    db.close()
    
    return render_template('admin_panel.html', surveys=surveys, forms=forms)

@app.route('/admin/delete_survey/<int:survey_id>', methods=['POST'])
@login_required(role='admin')
def delete_survey_admin(survey_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM responses WHERE survey_id = ?", (survey_id,))
        cursor.execute("DELETE FROM comments WHERE survey_id = ?", (survey_id,))
        cursor.execute("DELETE FROM surveys WHERE id = ?", (survey_id,))
        db.commit()
        flash('Survey successfully deleted!', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_form/<int:form_id>', methods=['POST'])
@login_required(role='admin')
def delete_form_admin(form_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM surveys WHERE id = ? AND type = 'form'", (form_id,))
        db.commit()
        flash('Form successfully deleted!', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        db.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/manage_users', methods=['GET'])
@login_required(role='admin')
def manage_users():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    db.close()
    return render_template('manage_users.html', users=users)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required(role='admin')
def delete_user(user_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM comments WHERE user IN (SELECT username FROM users WHERE id = ?)", (user_id,))
        cursor.execute("DELETE FROM surveys WHERE user IN (SELECT username FROM users WHERE id = ?)", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
        flash('User successfully deleted!', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error: {str(e)}', 'danger')
    finally:
        db.close()
    return redirect(url_for('manage_users'))

@app.route('/admin/view_notifications', methods=['GET'])
@login_required(role='admin')
def view_notifications():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM notifications ORDER BY timestamp DESC")
    notifications = cursor.fetchall()
    db.close()
    return render_template('view_notifications.html', notifications=notifications)

if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)