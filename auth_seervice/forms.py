from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, PasswordField, EmailField, SubmitField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Email, length, Length


class RegisterForm(FlaskForm):
    login = StringField('Имя пользователя', validators=[DataRequired(), Length(min=5, max=50)])
    password = PasswordField('Пароль', validators=[DataRequired(), length(min=5, max=50)])
    password2 = PasswordField('Повторите пароль',
                              validators=[DataRequired(""),
                                          EqualTo('password', message='Пароли не совпадают')])
    email = EmailField('Почта', validators=[DataRequired(), Email()])
    submit = SubmitField('Зарегистрироваться')

    def to_dict(self):
        return {
            'login': {
                'label': self.login.label.text,
                'type': 'text',
                'name': 'login',
                'value': self.login.data,
                'errors': self.login.errors,
            },
            'password': {
                'label': self.password.label.text,
                'type': 'password',
                'name': 'password',
                'value': self.password.data,
                'errors': self.password.errors,
            },
            'password2': {
                'label': self.password2.label.text,
                'type': 'password',
                'name': 'password2',
                'value': self.password2.data,
                'errors': self.password2.errors,
            },
            'email': {
                'label': self.email.label.text,
                'type': 'email',
                'name': 'email',
                'value': self.email.data,
                'errors': self.email.errors,
            },
            'submit': {
                'label': self.submit.label.text,
                'name': 'submit',
            }
        }


class LoginForm(FlaskForm):
    email = StringField('Адрес Электронной почты', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')
