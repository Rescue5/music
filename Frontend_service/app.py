from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests

from forms import RegisterForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dsaisv2u3hfqc7vw7c9b7bvb97w7cb'


@app.route('/')
def home():
    token = session.get('auth_token')
    if token:
        auth_response = requests.post('http://127.0.0.1:5001/check_auth', headers={'Authorization': token})
        if auth_response.status_code == 200:
            return render_template("home_logged.html")
        else:
            return render_template("home_unlogged.html")
    return render_template("home_unlogged.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        login = form.login.data
        password = form.password.data
        email = form.email.data
        try:
            response = requests.post('http://127.0.0.1:5001/register', data={'login': login,
                                                                             'password': password,
                                                                             'email': email})
            if response.status_code == 200:
                flash("Регистрация завершена, пожалуйста войдите в аккаунт")
                return redirect(url_for('login'))
            elif response.status_code == 409:
                flash(f"Пользователь с таким Email: \"{email}\" уже существует")
            elif response.status_code == 401:
                flash("Ошибка регистрации пользователя, попробуйте снова")
            else:
                flash(f"Непредвиденная ошибка: {response.json().get('message', 'Попробуйте позже')}")
        except Exception as e:
            print(f"Ошибка соединения с сервером: {str(e)}")
    return render_template("registration.html", form=form)


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
