import sqlite3
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Для сессий

# ← ВСТАВЬ СВОИ КЛЮЧИ ЗДЕСЬ ↓
RECAPTCHA_SITE_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'      # ← твой site key
RECAPTCHA_SECRET_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'    # ← твой secret key

# Для тестов удобно использовать тестовые ключи Google (они всегда проходят):
# Site key: 6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI
# Secret key: 6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe
# Но для резюме лучше использовать реальные свои ключи!

# Инициализация БД
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

def verify_recaptcha(response_token):
    if not RECAPTCHA_SECRET_KEY:
        return True  # для локального теста без ключей (убери в продакшене!)
    url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response_token,
        'remoteip': request.remote_addr  # опционально
    }
    r = requests.post(url, data=payload)
    result = r.json()
    return result.get('success', False)


@app.context_processor
def inject_recaptcha():
    return dict(recaptcha_site_key=RECAPTCHA_SITE_KEY)


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Серверная валидация
        if not username or not email or not password:
            flash('Все поля обязательны!')
            return render_template('register.html')
        if '@' not in email:
            flash('Невалидный email!')
            return render_template('register.html')
        if len(password) < 6:
            flash('Пароль должен быть минимум 6 символов!')
            return render_template('register.html')

        # Проверка reCAPTCHA
        if not verify_recaptcha(recaptcha_response):
            flash('Проверка reCAPTCHA не пройдена. Попробуйте снова.')
            return render_template('register.html')

        # Регистрация
        hashed_password = generate_password_hash(password)
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                           (username, email, hashed_password))
            conn.commit()
            flash('Регистрация успешна! Войдите.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Пользователь или email уже существует!')
        finally:
            conn.close()

    return render_template('register.html')

# Авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        recaptcha_response = request.form.get('g-recaptcha-response')

        if not email or not password:
            flash('Все поля обязательны!')
            return render_template('login.html')

        if not verify_recaptcha(recaptcha_response):
            flash('Проверка reCAPTCHA не пройдена. Попробуйте снова.')
            return render_template('login.html')

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль!')

    return render_template('login.html')

# Дашборд
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_username = request.form.get('new_username')
        if new_username:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, session['user_id']))
            conn.commit()
            conn.close()
            session['username'] = new_username
            flash('Имя обновлено!')

    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)