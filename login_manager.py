from flask_login import LoginManager, UserMixin, login_user, logout_user

login_manager = LoginManager()


class UserLogin(UserMixin):
    user = None
    id = None
    is_active = None

    def get_user_from_db(self, user_pk, db):
        self.user = db.get_user(user_pk)
        self.id = user_pk
        self.is_active = True
        return self

    def create(self, user):
        self.user = user
        self.id = user.user_pk
        self.is_active = True
        return self


