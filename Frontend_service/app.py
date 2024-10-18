from flask import Flask, render_template, request, redirect, url_for, session
import requests

app = Flask(__name__)


@app.route('/')
def home():
    token = session.get('auth_token')
    if token:
        auth_response = requests.post('http://127.0.0.1:5001/check_auth', headers={'Authorization': token})
        if auth_response.status_code == 200:
            return render_template("home_logged.html")
        else:
            return render_template("home_unlogged.html")
    return render_template("home_unlogged.html")


@app.route('/register', methods=['GET'])
def register():
    response = requests.get('http://127.0.0.1:5001/get_register_form')
    print(response)
    if response.status_code == 200:
        form_data = response.json().get('form', {})
        print(form_data)
        return render_template("registration.html", form=form_data)
    else:
        return "Error fetching form", 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
