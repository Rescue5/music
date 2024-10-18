from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
from werkzeug.security import generate_password_hash
import traceback
from functools import wraps

from forms import RegisterForm, LoginForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dsaisv2u3hfqc7vw7c9b7bvb97w7cb'


def check_auth():
    token = session.get('auth_token')
    if not token:
        return False
    try:
        response = requests.get('http://127.0.0.1:5001/check_auth', headers={'Authorization': 'Bearer ' + token})
        if not response or response.status_code != 200:
            return False
    except Exception as e:
        print(f"Ошибка при проверке токена {e}")
        return False
    return True


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('auth_token')
        if not token:
            flash('Пожалуйста, авторизируйтесь, чтобы получить доступ к этой странице', category='warning')
            return redirect(url_for('login'))
        try:
            response = requests.post('http://127.0.0.1:5001/check_auth', headers={'Authorization': 'Bearer ' + token})

            if not response or response.status_code != 200:
                flash('Пожалуйста, авторизируйтесь, чтобы получить доступ к этой странице', category="warning")
                return redirect(url_for('login'))
        except requests.exceptions.RequestException as e:
            flash("Ошибка при проверке авторизации, пожалуйста войдите в аккаунт повторно", category="warning")
            print(f"Ошибка при проверке токена: {e}")
            return redirect(url_for('logout'))

        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    if check_auth():
        return render_template("home_logged.html")
    return render_template("home_unlogged.html")


@app.route('/logout')
def logout():
    session['auth_token'] = None
    flash("Вы вышли из аккаунта")
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if check_auth():
        return redirect(url_for('profile'))

    form = LoginForm(request.form)
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        print(f"Пароль при логине {password}")
        remember_me = form.remember_me.data
        try:
            login_response = requests.post('http://127.0.0.1:5001/login', data={
                'email': email,
                'password': password,
                'remember_me': remember_me
            })
            if login_response.status_code == 200:
                data = login_response.json()
                token = data.get('token')
                if token:
                    session['auth_token'] = token
                    flash('Вы успешно авторизировались')
                    return redirect(url_for('profile'))
                else:
                    print(f"Не удалось создать токен для пользователя: {email}")
                    flash('Что-то пошло не так, пожалуйста повторите попытку позже')
            else:
                flash("Неверная пара E-mail/пароль", category='warning')

        except Exception as e:
            print(e)
            print(traceback.format_exc())
            flash("Что-то пошло не так, пожалуйста повторите попытку позже", category='warning')

    return render_template("login.html", form=form)


@app.route('/profile')
def profile():
    return "profile"


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_login = form.login.data
        password = generate_password_hash(form.password.data.strip())
        print(f"Пароль при регистрации: {password}")
        email = form.email.data
        try:
            response = requests.post('http://127.0.0.1:5001/register', data={
                'login': user_login,
                'password': password,
                'email': email
            })
            if response.status_code == 200:
                flash("Регистрация завершена, пожалуйста войдите в аккаунт")
                return redirect(url_for('login'))
            elif response.status_code == 409:
                flash(f"Пользователь с таким Email: \"{email}\" уже существует", category='warning')
            elif response.status_code == 401:
                flash("Ошибка регистрации пользователя, попробуйте снова", category='warning')
            else:
                flash(f"Непредвиденная ошибка: {response.json().get('message', 'Попробуйте позже')}")
        except Exception as e:
            print(f"Ошибка соединения с сервером: {str(e)}")
    return render_template("registration.html", form=form)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
