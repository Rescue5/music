import logging
import traceback
from logging.handlers import RotatingFileHandler

from flask import Flask, request
from flask_restful import Api, Resource
from models import FDataBase, Users, UserInfo, db

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s)')

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)

app = Flask(__name__)
# app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
fdb = FDataBase(db.session)
api = Api(app)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)


class RegisterUser(Resource):
    def post(self):
        """
        Регистрация пользователя
        ---
        tags:
          - Регистрация
        summary: Регистрация нового пользователя
        description: Метод регистрирует нового пользователя в системе, проверяя уникальность email. Если email уже существует, регистрация не будет выполнена.
        parameters:
          - name: login
            in: formData
            type: string
            required: true
            description: Логин нового пользователя
          - name: password
            in: formData
            type: string
            required: true
            description: Пароль нового пользователя
          - name: email
            in: formData
            type: string
            required: true
            description: Email нового пользователя
        responses:
          200:
            description: Пользователь успешно зарегистрирован
          409:
            description: Email занят
          401:
            description: Ошибка регистрации пользователя
          500:
            description: Непредвиденная ошибка сервера
        """
        user_login = request.form.get('login')
        password = request.form.get('password')
        email = request.form.get('email')
        try:
            email_not_exist = fdb.check_unique_email(email)
            if not email_not_exist:
                app.logger.warning(f"Попытка регистрации с занятым email: {email}")
                return {"message": "Email занят"}, 409
            res = fdb.register_new_users(user_login, password, email)
            if not res:
                app.logger.error(f"Ошибка при регистрации пользователя, register_new_users не "
                                 f"вернул значения для user_login: {user_login}, password: {password}, email: {email}")
                return {"message": "Ошибка регистрации пользователя"}, 401
            app.logger.info(f"Пользователь login: {user_login}, email: {email} успешно зарегистрирован")
            return {"message": "Пользователь успешно зарегистрирован"}, 200
        except Exception as e:
            app.logger.error(f"Непредвиденная ошибка при регистрации пользователя {user_login}: {e}")
            app.logger.error(f"Стек вызова ошибки: {traceback.format_exc()}")
            return {"message": f"Непредвиденная ошибка {e}"}, 500


class CheckLogin(Resource):
    def get(self):
        """
        Проверка логина пользователя
        ---
        tags:
          - Авторизация
        summary: Проверка логина и пароля пользователя
        description: Метод проверяет, соответствует ли пара email/пароль существующему пользователю в базе данных.
        parameters:
          - name: email
            in: query
            type: string
            required: true
            description: Email пользователя
          - name: password
            in: query
            type: string
            required: true
            description: Пароль пользователя
        responses:
          200:
            description: Email и пароль соответствуют, пользователя можно авторизировать
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: Статус операции
                user_id:
                  type: integer
                  description: Идентификатор пользователя
          400:
            description: Email и пароль обязательны
          401:
            description: Неверная пара Email/пароль
          500:
            description: Внутренняя ошибка сервера
        """
        email = request.args.get('email')
        password = request.args.get('password')

        if not email or not password:
            app.logger.error("Из запроса на проверку соответствия email/пароль"
                             " пользователя не было получено одно из полей")
            return {"message": "Email и пароль обязательны"}, 400
        user = fdb.authenticate(email, password)
        try:
            if not user:
                app.logger.warning("Неверная пара Email/пароль или ошибка при проверке")
                return {"message": "Неверная пара Email/пароль"}, 401

            app.logger.info(f"Проверка данных пользователя прошла успешно")
            return {"message": "Email и пароль соответствуют, пользователя можно авторизировать",
                    'user_id': user.user_pk}, 200
        except Exception as e:
            app.logger.error("Произошло исключение при проверке email/пароль")
            return {"message": f"Произошла ошибка при проверке email/пароль"}, 500


api.add_resource(RegisterUser, '/register')
api.add_resource(CheckLogin, '/login')
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5002)
