import json
import logging
import threading
import traceback
from logging.handlers import RotatingFileHandler

import requests
from flask import Flask, request
from flask_restful import Api, Resource
from flasgger import Swagger
from kafka import KafkaProducer, KafkaConsumer
from kafka.producer import kafka

import six
import sys

from kafka_handlers import (send_to_topic, get_message_from_topic, handle_profile_request,
                            handle_db_service_profile_responses)

if sys.version_info >= (3, 12, 0):
    sys.modules['kafka.vendor.six.moves'] = six.moves

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s)')

handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)

app = Flask(__name__)
app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
api = Api(app)
swagger = Swagger(app)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)


KAFKA_BROKER_URL = 'localhost:9092'

producer = KafkaProducer(
    api_version=(0, 11, 5),
    bootstrap_servers=KAFKA_BROKER_URL,
    value_serializer=lambda v: json.dumps(v).encode('utf-8'))

# Консумеры для топиков
consumer_profile_requests = KafkaConsumer(
    'user_profile_requests',
    bootstrap_servers=KAFKA_BROKER_URL,
    group_id='profile-group',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

consumer_profile_responses = KafkaConsumer(
    'db_service_profile_responses',
    bootstrap_servers=KAFKA_BROKER_URL,
    group_id='profile-group',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)


# Старт асинхронного прослушивания
def start_kafka_consumers():
    threading.Thread(target=get_message_from_topic('user_profile_requests'), daemon=True).start()
    threading.Thread(target=get_message_from_topic('db_service_profile_responses'), daemon=True).start()


class ItsCurrentUser(Resource):
    def get(self):
        try:
            auth_header = request.headers.get('Authorization')
            profile_id = request.headers.get('profile_id')

            if not auth_header:
                return self._handle_error("Не был получен токен, подтверждающий авторизацию для загрузки профиля",
                                          400)
            if not profile_id:
                return self._handle_error("Не был получен id загружаемого профиля", 400)
            response = requests.get('http://127.0.0.1:5001/check_auth',
                                    headers={'Authorization': 'Bearer ' + auth_header})
            return self._handle_auth_response(response, profile_id)
        except Exception as e:
            app.logger.error(f"Внутренняя ошибка при проверке профиля пользователя: {e}")
            app.logger.error(traceback.format_exc())
            return {"message": "Внутренняя ошибка"}, 500

    @staticmethod
    def _handle_error(message, status_code):
        app.logger.error(message)
        return {"message": message}, status_code

    @staticmethod
    def _handle_auth_response(response, profile_id):
        if response.status_code == 401:
            app.logger.warning("Токен пользователя истек или неверный формат токена, требуется повторная авторизация")
            return {"message": "Токен пользователя истек"}, 401

        if response.status_code == 500:
            app.logger.error("Внутренняя ошибка сервера авторизации")
            return {"message": "Внутренняя ошибка сервера авторизации"}, 500

        if response.status_code == 200:
            user_id = response.json().get('user_id')
            app.logger.info("id пользователя успешно получен из заголовка")

            if user_id == profile_id:
                app.logger.info("Пользователь зашел на свой профиль")
                return {"message": "id профиля соответствует id авторизации"}, 200
            else:
                app.logger.info("Пользователь зашел не на свой профиль")
                return {"message": "id профиля не соответствует id авторизации"}, 203

        return {"message": "Неизвестный статус ответа"}, 500


class UserProfileOwner(Resource):
    pass


api.add_resource(ItsCurrentUser, "/its_current_user")

if __name__ == '__main__':
    start_kafka_consumers()
    app.run(host='127.0.0.1', port=5003, debug=True)
