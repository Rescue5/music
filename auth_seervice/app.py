from flask import Flask, request, jsonify
import jwt
import datetime
import json
from forms import LoginForm, RegisterForm
from models import db, FDataBase

app = Flask(__name__)
app.config["SECRET_KEY"] = "daJsfohcub23rhqfcnqiu3dqobcqbbcq438fc"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
fdb = FDataBase(db)


@app.route('/register', methods=['POST'])
def register():
    form = RegisterForm(request.form)
    if form.validate_on_submit():
        login = form.login.data
        password = form.password.data
        email = form.email.data
        if fdb.register_new_users(login, password, email):
            return jsonify({'message': 'User registered successfully'}), 201
        else:
            return jsonify({'message': 'User registration failed'}), 400
    return jsonify({'message': 'Invalid input'}), 400


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = fdb.authenticate(email, password)
        if user:
            token = jwt.encode({'user_id': user.user_pk, 'exp': datetime.datetime.now() + datetime.timedelta(hours=1)},
                               app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'token': token}), 200
        return jsonify({'message': 'Login failed'}), 401
    return jsonify({'message': 'Invalid input'}), 400


@app.route('/check_auth', methods=['GET'])
def check_auth():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': "Token is missing"}), 401

    try:
        token = token.split(' ')[1]
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return jsonify({'message': "Authenticated", 'user_id': data['user_id']}), 200
    except jwt.ExpiredSignatureError as e:
        return jsonify({'message': 'Token is expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'message': 'Invalid token'}), 401


@app.route('/get_register_form', methods=['GET'])
def get_register_form():
    print("Пытаюсь получить форму")
    form = RegisterForm()
    if form:
        print("Форма получена успешно")
        dict_form = form.to_dict()
        return jsonify({
            'form': dict_form
            # 'csrf_token': form.csrf_token.current_token
        }), 200
    else:
        print("Не удалось получить форму")
        return jsonify({'message': 'Form does not exist'}), 400


if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=5001)
