from flask import Flask, render_template, redirect, flash, url_for, request
from flask_login import LoginManager, current_user

from DB_Models import FDataBase, db
from forms import RegisterForm, LoginForm

from flask_login import login_user, logout_user, login_required
from login_manager import login_manager, UserLogin


# Инициализируем приложение
app = Flask(__name__)
app.config['SECRET_KEY'] = '30a469afa9bd791e087d03e29a68e57cbc6e1c9a'

# инициализация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
fdb = FDataBase(db.session)

# инициализация login manager
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Чтобы получить доступ к этой странице авторизируйтесь'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return UserLogin().get_user_from_db(user_id, fdb)


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


@app.route('/login', methods=['GET', 'POST'])
def login():
    print(current_user.is_authenticated)
    if current_user.is_authenticated:
        return redirect(request.args.get("next") or url_for('profile'))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        remember_me = form.remember_me.data
        user = fdb.authenticate(email, password)
        if user:
            user_login = UserLogin().create(user)
            login_user(user_login, remember_me)
            return redirect(request.args.get("next") or url_for('profile'))
    return render_template("login.html", form=form)


@app.route('/profile')
@login_required
def profile():
    return 'profile'


if __name__ == '__main__':
    app.run(debug=True)
