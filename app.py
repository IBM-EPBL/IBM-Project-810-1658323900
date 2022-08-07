from flask import Flask, request, render_template, redirect, make_response

from db import create_user, authentication

app = Flask(__name__)

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', title='Error - 404 Page Not Found', page="misc")



@app.route('/accounts/user/login/', methods=['GET', 'POST'])
def user_login():
    if(request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'user')
        if(not secret_key):
            values = {"email": email, "password": password}
            return render_template("login.html", user='user', title='User Login', page="auth", values=values, error="Incorrect login credentials")
        response = make_response(redirect('/accounts/user/login/'))
        response.set_cookie('key', secret_key)
        return response

    return render_template("login.html", user='user', title='User Login', page="auth")


@app.route('/accounts/user/register/', methods=['GET', 'POST'])
def register_user():
    if (request.method == 'POST'):
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        secret_key = create_user(name, email, 'user', password)
        values = {"email": email, "name": name, "password": password}
        if(not secret_key):
            return render_template("register.html", user='user', title='Register User', page="auth", emailExists=True, values=values)

        return "success"

    return render_template("register.html", user='user', title='Register User', page="auth")


@app.route('/accounts/agent/login/', methods=['GET', 'POST'])
def staff_login():
    if (request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'agent')
        if (not secret_key):
            values = {"email": email, "password": password}
            return render_template("login.html", user='agent', title='Agent Login', page="auth", values=values,
                                   error="Incorrect login credentials")
        # request.cookies.add('key', secret_key)
        response = make_response(redirect('/accounts/agent/login/'))
        response.set_cookie('key', secret_key)
        return response

    return render_template("login.html", user='user', title='Agent Login', page="auth")



@app.route('/accounts/admin/login/', methods=['GET', 'POST'])
def admin_login():
    if (request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'admin')
        if (not secret_key):
            values = {"email": email, "password": password}
            return render_template("login.html", user='admin', title='Admin Login', page="auth", values=values,
                                   error="Incorrect login credentials")
        # request.cookies.add('key', secret_key)
        response = make_response(redirect('/accounts/admin/login/'))
        response.set_cookie('key', secret_key)
        return response

    return render_template("login.html", user='admin', title='Admin Login', page="auth")


if __name__ == '__main__':
    app.run(debug=True)