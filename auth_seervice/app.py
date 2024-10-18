from flask import Flask, request
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_restful import Api, Resource
from flasgger import Swagger

import datetime
import traceback

from models import db, FDataBase


app = Flask(__name__)
app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
fdb = FDataBase(db.session)

api = Api(app)
swagger = Swagger(app)


class Register(Resource):
    @staticmethod
    def post():
        """
        Зарегистрировать нового пользователя
        ---
        parameters:
          - name: login
            in: formData
            type: string
            required: true
            description: Логин пользователя
          - name: password
            in: formData
            type: string
            required: true
            description: Пароль пользователя
          - name: email
            in: formData
            type: string
            required: true
            description: Email пользователя
        responses:
          200:
            description: Пользователь успешно зарегистрирован
          409:
            description: Email занят
          401:
            description: Ошибка регистрации пользователя
          500:
            description: Непредвиденная ошибка
        """
        user_login = request.form.get('login')
        password = request.form.get('password')
        email = request.form.get('email')
        try:
            email_not_exist = fdb.check_unique_email(email)
            if not email_not_exist:
                return {"message": "Email занят"}, 409
            res = fdb.register_new_users(user_login, password, email)
            if not res:
                return {"message": "Ошибка регистрации пользователя"}, 401
            return {"message": "Пользователь успешно зарегистрирован"}, 200
        except Exception as e:
            print(f"Ошибка при обработке запроса: {e}")
            print(traceback.print_exc())
            return {"message": f"Непредвиденная ошибка {e}"}, 500


class Login(Resource):
    @staticmethod
    def post():
        """
        Авторизовать пользователя
        ---
        parameters:
          - name: email
            in: formData
            type: string
            required: true
            description: Email пользователя
          - name: password
            in: formData
            type: string
            required: true
            description: Пароль пользователя
          - name: remember_me
            in: formData
            type: boolean
            required: false
            description: Запомнить пользователя
        responses:
          200:
            description: Токен успешно получен
          400:
            description: Email и пароль обязательны
          401:
            description: Неверная пара Email/пароль
        """
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        password = password.strip()

        if not email or not password:
            return {"message": "Email и пароль обязательны"}, 400

        user = fdb.authenticate(email, password)
        if not user:
            return {"message": "Неверная пара Email/пароль"}, 401

        token_life_time = 720 if remember_me else 1
        token = jwt.encode({
            'user_id': user.user_pk,
            'exp': datetime.datetime.now() + datetime.timedelta(hours=token_life_time)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        return {'token': token}, 200


class CheckAuth(Resource):
    @staticmethod
    def get():
        """
        Проверить авторизацию пользователя
        ---
        parameters:
          - name: Authorization
            in: header
            type: string
            required: true
            description: Токен в формате "Bearer <token>"
        responses:
          200:
            description: Пользователь авторизирован
          401:
            description: Токен не предоставлен или истек
          500:
            description: Непредвиденная ошибка
        """
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {"message": "Токен не предоставлен"}, 401

        try:
            token = auth_header.split(' ')[1]
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if datetime.datetime.now() > datetime.datetime.fromtimestamp(decoded_token['exp']):
                return {"message": "Токен истек"}, 401

            return {"message": "Пользователь авторизирован", "user_id": decoded_token['user_id']}, 200

        except ExpiredSignatureError:
            return {"message": "Токен истек"}, 401
        except InvalidTokenError:
            return {"message": "Неверный токен"}, 401
        except Exception as e:
            print(f"Ошибка: {str(e)}")
            return {"message": "Непредвиденная ошибка"}, 500


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(CheckAuth, '/check_auth')


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
