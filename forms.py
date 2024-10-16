from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, length, Length


class RegisterForm(FlaskForm):
    login = StringField('Имя пользователя', validators=[DataRequired(), Length(min=5, max=50)])
    password1 = PasswordField('Пароль', validators=[DataRequired(), length(min=5, max=50)])
    password2 = PasswordField('Повторите пароль',
                              validators=[DataRequired(""),
                                          EqualTo('password', message='Пароли не совпадают')])
    email = EmailField('Почта', validators=[DataRequired(), Email()])
    submit = SubmitField('Зарегистрироваться')