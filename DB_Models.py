from datetime import datetime
from sqlalchemy import Column, Integer, String, SQ, Boolean, DateTime, TIMESTAMP
from sqlalchemy.exc import SQLAlchemyError
from app import db


class FDataBase:
    def __init__(self, db_session):
        self.__db_session = db_session

    def get_all_users(self):
        try:
            users = self.__db_session.Users.query.all()
            return [user.to_dict() for user in users]
        except SQLAlchemyError as e:
            print(f"Ошибка при получении списка пользователей: {e}")
            return []

    def register_new_users(self, login, password, email):
        try:
            existing_users = self.__db_session.Users.query.filter_by(login=login).first()
            if existing_users:
                print(f"Пользователь с логином: {login}, уже существует.")
                return None

            new_user = Users(login=login, password=password, email=email)

            self.__db_session.add(new_user)
            self.__db_session.flush()
            self.__db_session.commit()

            print(f"Пользователь {login} успешно зарегистрирован")
            return new_user
        except SQLAlchemyError as e:
            print(f"Ошибка регистрации пользователя {e}")
            self.__db_session.rollback()
            return None


class Users(db.Model):
    user_pk = db.column(db.Integer, primary_key=True)
    login = db.column(db.String(), unique=True, nullable=False)
    password = db.column(db.String(), nullable=False)
    email = db.column(db.String(), unique=True, nullable=False)
    email_confirm = db.column(db.Boolean(), default=False, nullable=False)
    reg_time = db.column(db.TimeStamp(), nullable=False, default=datetime.now())

    def to_dict(self):
        return {
            'user_pk': self.user_pk,
            'login': self.login,
            'email': self.email,
            'email_confirm': self.email_confirm
        }
