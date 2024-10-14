from flask import Flask, render_template, request, redirect
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy


# Инициализируем приложение
app = Flask(__name__)

# инициализация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://root:root@localhost/root'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# инициализация login manager


@app.route('/')
def home():
    return render_template('home_unlogged.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    pass



if __name__ == '__main__':
    app.run(debug=True)
