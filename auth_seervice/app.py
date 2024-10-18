from flask import Flask, request, jsonify
import jwt
import datetime
import traceback

from sqlalchemy.testing.pickleable import User

from models import db, FDataBase

app = Flask(__name__)
app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
fdb = FDataBase(db.session)


@app.route('/register', methods=['POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    email = request.form.get('email')
    try:
        email_not_exist = fdb.check_unique_email(email)
        if not email_not_exist:
            return jsonify({"message": "Email занят"}), 409
        res = fdb.register_new_users(login, password, email)
        if not res:
            return jsonify({"message": "Ошибка регистрации пользователя"}), 401
        return jsonify({"message": "Пользователь успешно зарегистрирован"}), 200
    except Exception as e:
        print(f"Ошибка при обработке запроса: {e}")
        print(traceback.print_exc())
        return jsonify({"message": f"Непредвиденная ошибка {e}"}), 500


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = fdb.authenticate(email, password)
        if user:
            token = jwt.encode({'user_id': user.user_pk, 'exp': datetime.datetime.now() + datetime.timedelta(hours=1)},
                               app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token}), 200
        return jsonify({'message': 'Login failed'}), 401
    return jsonify({'message': 'Invalid input'}), 400


@app.route('/check_auth', methods=['GET'])
def check_auth():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': "Token is missing"}), 401

    try:
        token = token.split(' ')[1]
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': "Authenticated", 'user_id': data['user_id']}), 200
    except jwt.ExpiredSignatureError as e:
        return jsonify({'message': 'Token is expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'message': 'Invalid token'}), 401


@app.route('/get_register_form', methods=['GET'])
def get_register_form():
    print("Пытаюсь получить форму")
    form = RegisterForm()
    if form:
        print("Форма получена успешно")
        dict_form = form.to_dict()
        return jsonify({
            'form': dict_form
            # 'csrf_token': form.csrf_token.current_token
        }), 200
    else:
        print("Не удалось получить форму")
        return jsonify({'message': 'Form does not exist'}), 400


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
