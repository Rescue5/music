from flask import Flask, render_template, request, redirect, flash, url_for
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from DB_Models import Users, FDataBase, db
from forms import RegisterForm



# Инициализируем приложение
app = Flask(__name__)
app.config['SECRET_KEY'] = '30a469afa9bd791e087d03e29a68e57cbc6e1c9a'

# инициализация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
fdb = FDataBase(db.session)

# инициализация login manager



@app.route('/')
def home():
    return render_template('home_unlogged.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        login = form.login.data
        password = form.password.data
        email = form.email.data
        res = fdb.register_new_users(login, password, email)
        if res:
            print("Пользователь успешно зарегистрирован")
            flash("Регистрация успешна, пожалуйста войдите в аккаунт")
            return redirect(url_for("login"))
        else:
            pass
            # flash("Ошибка при регистрации, проверьте введенные данные или попробуйте позже")
    return render_template('registration.html', form=form)





if __name__ == '__main__':
    app.run(debug=True)
