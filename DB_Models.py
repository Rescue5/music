from datetime import datetime

from flask import flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Boolean, DateTime, TIMESTAMP
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


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
            existing_users = Users.query.filter_by(login=login).first()
            if existing_users:
                flash(f"Пользователь с логином: {login}, уже существует.", category="warning")
                print(f"Пользователь с логином: {login}, уже существует.")
                return None
            existing_emails = Users.query.filter_by(email=email).first()
            if existing_emails:
                flash(f"Email адрес {email} уже зарегистрирован", category="warning")
                print(f"Email адрес {email} уже зарегистрирован")
                return None


            hashed_pass = generate_password_hash(password)
            new_user = Users(login=login, password=hashed_pass, email=email)

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
    __tablename__ = 'users'  # Опционально: задает имя таблицы в БД

    user_pk = Column(Integer(), primary_key=True, autoincrement=True)
    login = Column(String(), unique=True, nullable=False)
    password = Column(String(), nullable=False)
    email = Column(String(), unique=True, nullable=False)
    email_confirm = Column(Boolean(), default=False, nullable=False)
    reg_time = Column(TIMESTAMP(), nullable=False, default=datetime.now())

    def to_dict(self):
        return {
            'user_pk': self.user_pk,
            'login': self.login,
            'email': self.email,
            'email_confirm': self.email_confirm
        }
