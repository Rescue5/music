import traceback
from profile_servise.app import app, producer


def send_to_topic(profile_data, topic):
    try:
        producer.send(f'{topic}', profile_data)
        app.logger.info(f'Отправлен запрос в топик: {topic}')
    except Exception as e:
        app.logger.error(f"Ошибка отправки запроса в топик {e}")
        app.logger.error(traceback.format_exc())


def get_message_from_topic(topic):
    try:
        for message in topic:
            app.logger.info(f'Получен запрос: {message.value}')
            if topic == 'user_profile_requests':
                handle_profile_request(message.value)
            elif topic == 'db_service_profile_responses':
                handle_db_service_profile_responses(message.value)
    except Exception as e:
        app.logger.error(f"Ошибка обработки сообщения: {e}")
        app.logger.error(traceback.format_exc())


def handle_profile_request(user_id):
    send_to_topic(user_id, f'db_service_profile_requests')


def handle_db_service_profile_responses(profile_data):
    send_to_topic(profile_data, f'user_profile_response')