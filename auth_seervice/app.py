from flask import Flask, request, jsonify
import jwt
import datetime
import traceback
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.testing.pickleable import User
from werkzeug.security import generate_password_hash

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
    email = request.form.get('email')
    password = request.form.get('password')
    remember_me = request.form.get('remember_me')
    password = password.strip()

    if not email or not password:
        print("Недостаточно данных для авторизации")
        return jsonify({"message": "Email и пароль обязательны"}), 400

    user = fdb.authenticate(email, password)
    if user:
        print("Ошибка при поиске пользователя или сравнении пароля")
        return jsonify({"message": "Неверная пара Email/пароль"}), 401

    if remember_me:
        token_life_time = 720
    else:
        token_life_time = 1

    token = jwt.encode({
        'user_id': user.user_pk,
        'exp': datetime.datetime.now() + datetime.timedelta(hours=token_life_time)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token}), 200


@app.route('/check_auth', methods=['GET'])
def check_auth():
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"message": "Токен не предоставлен"}), 401

    try:
        token = auth_header.split(' ')[1]
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        if datetime.datetime.now() > datetime.datetime.fromtimestamp(decoded_token['exp']):
            return jsonify({"message": "Токен истек"}), 401

        return jsonify({"message": "Пользователь авторизирован", "user_id": decoded_token['user_id']}), 200

    except ExpiredSignatureError as e:
        return jsonify({"message": "Токен истек"}), 401
    except InvalidTokenError as e:
        return jsonify({"message", "Неверный токен"}), 401


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
