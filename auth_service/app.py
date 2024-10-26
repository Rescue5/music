import requests
from flask import Flask, request
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_restful import Api, Resource
from flasgger import Swagger
import datetime
import traceback
import logging
from logging.handlers import RotatingFileHandler

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s)')

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)


app = Flask(__name__)
app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

api = Api(app)
swagger = Swagger(app)


class Register(Resource):
    @staticmethod
    def post():
        """
        Зарегистрировать нового пользователя через микросервис
        ---
        tags:
          - Пользователи
        description: Отправляет запрос к микросервису по работе с БД для регистрации нового пользователя. В случае успеха, возвращает сообщение о регистрации. Обрабатывает ошибки, включая занятый email, неправильные данные или ошибки сервера.
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
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: Пользователь зарегистрирован
          409:
            description: Email уже используется
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: Email занят
          401:
            description: Ошибка при регистрации пользователя
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: Ошибка регистрации пользователя
          500:
            description: Внутренняя ошибка сервера
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: Непредвиденная ошибка
        """
        user_login = request.form.get('login')
        password = request.form.get('password')
        email = request.form.get('email')
        try:
            response = requests.post('http://127.0.0.1:5002/register', data={
                'login': user_login,
                'password': password,
                'email': email
            })
            if not response:
                app.logger.error('Не получен ответ от микросервиса для работы с БД при попытке регистрации пользователя')
                return {'message': 'Ошибка регистрации пользователя'}, 401
            if response.status_code == 401:
                app.logger.error('Микросервис для работы с БД вернул ошибку при попытке регистрации нового пользователя')
                return {'message': 'Ошибка регистрации пользователя'}, 401
            if response.status_code == 409:
                app.logger.warning(f'Попытка регистрации с занятым email: {email}')
                return {'message': 'Email занят'}, 409
            if response.status_code == 500:
                app.logger.error("Произошла непредвиденная ошибка на строне микросервиса по работе "
                                 "с БД при регистрации пользователя")
                return {'message': 'Непредвиденная ошибка'}, 500
            if response.status_code == 200:
                app.logger.info(f'Пользователь email: {email}, успешно зарегистрирован')
                return {'message': 'Пользователь зарегистрирован'}, 200
        except Exception as e:
            app.logger.error(f"Исключение при попытке обращения к микросервису по работе с БД {e}")
            app.logger.error(traceback.format_exc())
            return {'message': 'Ошибка запроса'}, 500


class Login(Resource):
    @staticmethod
    def post():
        """
        Авторизация пользователя
        ---
        tags:
          - Авторизация
        summary: Авторизация пользователя
        description: Метод авторизации пользователя по email и паролю. В случае успешной авторизации возвращает JWT токен. Опционально можно использовать параметр `remember_me` для продления срока действия токена.
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
            description: Флаг, указывающий на необходимость продлить срок действия токена. Если True — токен действителен 720 часов, если False — 1 час.
        responses:
          200:
            description: Успешная авторизация. Возвращает JWT токен.
            schema:
              type: object
              properties:
                token:
                  type: string
                  description: JWT токен, необходимый для последующих запросов
          400:
            description: Ошибка валидации данных (например, не передан email или пароль)
          401:
            description: Неверная пара Email/пароль
          500:
            description: Внутренняя ошибка сервера
        """
        email = request.form.get('email')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me')
        try:
            response = requests.get('http://127.0.0.1:5002/login', params={'email': email, 'password':password})
            if not response:
                app.logger.error("Не получен ответ от микросервиса для работы с БД при попытке авторизации пользователя")
                return {'message': 'Ошибка авторизации пользователя'}, 401
            if response.status_code == 400:
                app.logger.error("Ошибка при доставке данных к микросервису по работе с БД")
                return {'message': 'Ошибка авторизации пользователя'}, 400
            if response.status_code == 401:
                app.logger.warning("Неверная пара Email/пароль или ошибка при проверке")
                return {'message': 'Неверная пара Email/пароль'}, 401
            if response.status_code == 500:
                app.logger.error("Произошла непредвиденная ошибка на строне микросервиса по работе "
                                 "с БД при авторизации пользователя")
                return {'message': 'Непредвиденная ошибка'}, 500
            if response.status_code == 200:
                user_id = response.json()['user_id']
                token_life_time = 720 if remember_me else 1
                token = jwt.encode({
                    'user_id': user_id,
                    'exp': datetime.datetime.now() + datetime.timedelta(hours=token_life_time)
                }, app.config['SECRET_KEY'], algorithm='HS256')

                app.logger.info(f"Пользователь {user_id} успешно вошел в аккаунт и авторизирован")
                return {'token': token}, 200
        except Exception as e:
            app.logger.error(f"Произошло исключение в процессе авторизации пользователя: {e}")
            app.logger.error(traceback.format_exc())
            return {'message': 'Непредвиденная ошибка'}, 500


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
            app.logger.error("При проверке авторизации в запросе отсутствует токен")
            return {"message": "Токен не предоставлен"}, 401

        try:
            token = auth_header.split(' ')[1]
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if datetime.datetime.now() > datetime.datetime.fromtimestamp(decoded_token['exp']):
                app.logger.info(f"Токен пользователя {decoded_token['user_id']} истек")
                return {"message": "Токен истек"}, 401

            app.logger.info(f"Пользователь {decoded_token['user_id']} авторизирован")
            return {"message": "Пользователь авторизирован", "user_id": decoded_token['user_id']}, 200

        except ExpiredSignatureError as e:
            app.logger.error(f"Токен истек: {e}")
            return {"message": "Токен истек"}, 401
        except InvalidTokenError as e:
            app.logger.error(f"Неверный формат токента: {e}")
            return {"message": "Неверный токен"}, 401
        except Exception as e:
            app.logger.error(f"Непредвиденная ошибка при проверке токена: {e}")
            return {"message": "Непредвиденная ошибка"}, 500


api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(CheckAuth, '/check_auth')


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
