import sys
import os
import pytest
from unittest.mock import patch
import sqlite3

# ←←← ДОБАВЬ ЭТИ 3 СТРОКИ В САМОЕ НАЧАЛО ФАЙЛА ←←←
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, init_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        # Полностью пересоздаём БД перед каждым тестом
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('DROP TABLE IF EXISTS users')
        conn.commit()
        conn.close()
        init_db()
        yield client


# Мок для reCAPTCHA — всегда успешно проходит в тестах
@pytest.fixture(autouse=True)
def mock_recaptcha(monkeypatch):
    def mock_verify(response_token):
        return True
    monkeypatch.setattr("app.verify_recaptcha", mock_verify)


# Остальные тесты без изменений
def test_register_success(client):
    response = client.post('/register', data={
        'username': 'testuser1',
        'email': 'test1@example.com',
        'password': 'strongpass123',
        'g-recaptcha-response': 'fake-token-for-tests'
    }, follow_redirects=True)

    assert response.status_code == 200
    assert "Регистрация успешна! Войдите." in response.data.decode('utf-8')

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users WHERE email = 'test1@example.com'")
    user = cursor.fetchone()
    conn.close()
    assert user is not None
    assert user[0] == 'testuser1'


def test_register_empty_fields(client):
    response = client.post('/register', data={
        'username': '',
        'email': '',
        'password': '',
        'g-recaptcha-response': 'fake-token'
    })
    assert "Все поля обязательны!" in response.data.decode('utf-8')


def test_register_invalid_email(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'not-an-email',
        'password': 'strongpass123',
        'g-recaptcha-response': 'fake-token'
    })
    assert "Невалидный email!" in response.data.decode('utf-8')


def test_register_short_password(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': '123',
        'g-recaptcha-response': 'fake-token'
    })
    assert "Пароль должен быть минимум 6 символов!" in response.data.decode('utf-8')


def test_register_duplicate_email(client):
    client.post('/register', data={
        'username': 'user1',
        'email': 'duplicate@example.com',
        'password': 'strongpass123',
        'g-recaptcha-response': 'fake-token'
    })

    response = client.post('/register', data={
        'username': 'user2',
        'email': 'duplicate@example.com',
        'password': 'strongpass123',
        'g-recaptcha-response': 'fake-token'
    })
    assert "Пользователь или email уже существует!" in response.data.decode('utf-8')


def test_login_success(client):
    client.post('/register', data={
        'username': 'loginuser',
        'email': 'login@example.com',
        'password': 'mypassword456',
        'g-recaptcha-response': 'fake-token'
    })

    response = client.post('/login', data={
        'email': 'login@example.com',
        'password': 'mypassword456',
        'g-recaptcha-response': 'fake-token'
    }, follow_redirects=True)

    html = response.data.decode('utf-8')
    assert "Привет, loginuser!" in html
    assert "Обновить имя:" in html


def test_login_wrong_password(client):
    client.post('/register', data={
        'username': 'wrongpass',
        'email': 'wrong@example.com',
        'password': 'correct123',
        'g-recaptcha-response': 'fake-token'
    })

    response = client.post('/login', data={
        'email': 'wrong@example.com',
        'password': 'incorrect',
        'g-recaptcha-response': 'fake-token'
    })
    assert "Неверный email или пароль!" in response.data.decode('utf-8')


def test_dashboard_update_username(client):
    client.post('/register', data={
        'username': 'oldname',
        'email': 'update@example.com',
        'password': 'pass789',
        'g-recaptcha-response': 'fake-token'
    })
    client.post('/login', data={
        'email': 'update@example.com',
        'password': 'pass789',
        'g-recaptcha-response': 'fake-token'
    })

    response = client.post('/dashboard', data={
        'new_username': 'newcoolname'
    }, follow_redirects=True)

    html = response.data.decode('utf-8')
    assert "Привет, newcoolname!" in html
    assert "Имя обновлено!" in html


def test_logout(client):
    client.post('/register', data={
        'username': 'logoutuser',
        'email': 'logout@example.com',
        'password': 'logoutpass',
        'g-recaptcha-response': 'fake-token'
    })
    client.post('/login', data={
        'email': 'logout@example.com',
        'password': 'logoutpass',
        'g-recaptcha-response': 'fake-token'
    })

    response = client.get('/logout', follow_redirects=True)
    html = response.data.decode('utf-8')
    assert "Авторизация" in html
    assert "Войти" in html


def test_sql_injection_attempt(client):
    malicious_input = "test'); DROP TABLE users; --"

    client.post('/register', data={
        'username': malicious_input,
        'email': 'injection@example.com',
        'password': 'pass12345',
        'g-recaptcha-response': 'fake-token'
    })

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = cursor.fetchone() is not None
    conn.close()

    assert table_exists is True