from flask import Flask, request, render_template, redirect, make_response, url_for, session
from db import create_user, authentication, is_authenticated, user_details, create_ticket, fetch_user_tickets, \
    delete_user_ticket, update_user_ticket, agent_details, fetch_agent_tickets, set_ticket_status, admin_details, \
    fetch_all_tickets, fetch_all_agents, set_ticket_agent, fetch_requested_users, accept_or_reject, check_user, \
    change_password, dashboard_details
from mail import SendGrid
from random import randint

app = Flask(__name__)
app.debug = True
app.secret_key = "CustomerCareRegistry"

send_mail = SendGrid()

@app.errorhandler(404)
def not_found(e):
    return render_template('error/404.html', title='Error - 404 Page Not Found')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/accounts/user/login/', methods=['GET', 'POST'])
def user_login():
    cookies = request.cookies.get('key')
    if(is_authenticated(cookies, 'user')):
        return redirect(url_for('user_dashboard'))
    if(request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'user')
        if(not secret_key):
            values = {"email": email, "password": password}
            return render_template("auth/login.html", user='user', title='User Login', values=values, error="Incorrect login credentials")
        response = make_response(redirect(url_for('user_login')))
        response.set_cookie('key', secret_key)
        return response

    return render_template("auth/login.html", user='user', title='User Login')


@app.route('/accounts/forgot-password/', methods=['GET', 'POST'])
def forgot_password():
    email = request.args.get('email')
    if (request.method == 'POST'):
        print(session["otp"])
        otp = request.form.get('otp')
        if (otp == session["otp"]):
            return redirect(url_for('reset_password'))
        return render_template('auth/OTP.html', title='Verification', email=session["email"], otp=otp, error="Incorrect OTP")
    elif(email):
        otp = str(randint(00000, 99999))
        print(otp)
        send_mail.send_otp(email, otp)
        user = check_user(email)
        if(user):
            session["email"] = email
            session["otp"] = otp
            return render_template('auth/OTP.html', title='Verification', email=email)
        return render_template('auth/forget-password.html', title='Forgot Password', email=email, error="No user with this email")

    return render_template('auth/forget-password.html', title='Forgot Password')


@app.route('/accounts/reset-password/', methods=['GET', 'POST'])
def reset_password():
    if("email" in session):
        if(request.method == 'POST'):
            email = session["email"]
            password = request.form.get('password')
            user = change_password(email, password)
            return redirect(url_for(user[3]+'_login', success="Password Updated"))

        return render_template('auth/reset-password.html', title='Reset Password')

    return redirect(url_for('forgot_password'))


@app.route('/accounts/user/register/', methods=['GET', 'POST'])
def register_user():
    if (request.method == 'POST'):
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        secret_key = create_user(name, email, 'user', password)
        values = {"email": email, "name": name, "password": password}
        if(not secret_key):
            return render_template("auth/register.html", user='user', title='Register User', emailExists=True, values=values)

        send_mail.welcome_user(email, name)

        return redirect(url_for('user_login'))

    return render_template("auth/register.html", user='user', title='Register User')


@app.route('/user/dashboard/')
def user_dashboard():
    cookies = request.cookies.get('key')
    if(not cookies):
        return redirect(url_for('user_login'))
    if(not is_authenticated(cookies, 'user')):
        return redirect(url_for('user_login'))
    user = user_details(secret_key=cookies)
    details = dashboard_details(user_id=user[0])
    return render_template("dashboard/user/dashboard.html", user=user, title="Dashboard", details=details, page="dashboard")


@app.route('/user/tickets/create/', methods=['GET', 'POST'])
def create_tickets():
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'user')):
        return redirect(url_for('user_login'))

    user = user_details(secret_key=cookies)

    if request.method=="GET":
        return render_template("dashboard/user/create-ticket.html", user=user, title='Create Ticket')

    if request.method=="POST":
        description = request.form.get('ticket-description')
        issue = request.form.get('ticket-issue')
        ticket_id = create_ticket(cookies, description, issue)

        send_mail.new_ticket(user[2], ticket_id, description, issue)

        return redirect(url_for('user_tickets', status='all', success="Raised new Ticket"))


@app.route('/user/ticket/<id>')
def user_ticket_detail(id):
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'user')):
        return redirect(url_for('user_login'))
    user = user_details(secret_key=cookies)

    ticket = fetch_user_tickets(user_id=user[0], ticket_id=id)

    return render_template("dashboard/user/ticket.html", user=user, ticket=ticket)



@app.route('/user/tickets/update/<ticket_id>/', methods=['POST'])
def update_tickets(ticket_id):
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'user')):
        return redirect(url_for('user_login'))
    description = request.form.get('ticket-description')
    issue = request.form.get('ticket-issue')
    user = user_details(secret_key=cookies)
    update_user_ticket(user[0], ticket_id, description, issue)
    return redirect(request.referrer)


@app.route('/user/tickets/delete/<ticket_id>/')
def delete_tickets(ticket_id):
    cookies = request.cookies.get('key')
    is_user = is_authenticated(cookies, 'user')
    is_admin = is_authenticated(cookies, 'admin')
    if(is_user):
        user = user_details(secret_key=cookies)
        delete_user_ticket(user[0], ticket_id)
        return redirect(url_for('user_tickets', status='all', success="Deleted Ticket"))
    elif(is_admin):
        user = admin_details(secret_key=cookies)
        delete_user_ticket(ticket_id=ticket_id)
        return redirect(url_for('all_tickets', status='all', success="Deleted Ticket"))
    else:
        return redirect(url_for('user_login'))


@app.route('/user/tickets/<status>/')
def user_tickets(status):
    success = (request.args.get("success"))
    if(status not in ['all', 'open', 'pending', 'on-hold', 'solved', 'closed']):
        return render_template('error/404.html', title='Error - 404 Page Not Found', back='/user/tickets/all/')
    cookies = request.cookies.get('key')
    if(not is_authenticated(cookies, 'user')):
        return redirect(url_for('user_login'))
    user = user_details(secret_key=cookies)
    if(status == 'all'):
        tickets = fetch_user_tickets(user[0])
    elif(status == 'on-hold'):
        tickets = fetch_user_tickets(user_id=user[0], status='On Hold')
    else:
        tickets = fetch_user_tickets(user_id=user[0], status=status.title())

    return render_template("dashboard/user/tickets.html", title=f'{status.title()} Tickets', user=user, tickets=tickets, page=status, success=success)


@app.route('/accounts/agent/login/', methods=['GET', 'POST'])
def agent_login():
    cookies = request.cookies.get('key')
    if (cookies):
        if (is_authenticated(cookies, 'agent')):
            return redirect(url_for('agent_dashboard'))
    if (request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'agent')
        if (not secret_key):
            values = {"email": email, "password": password}
            secret_key = authentication(email, password, 'r-agt')
            if(secret_key):
                return render_template("auth/login.html", user='agent', title='Agent Login', values=values,
                                       error="Account Verification Pending")

            return render_template("auth/login.html", user='agent', title='Agent Login', values=values,
                                   error="Incorrect login credentials")
        response = make_response(redirect('/accounts/agent/login/'))
        response.set_cookie('key', secret_key)
        return response

    return render_template("auth/login.html", user='agent', title='Agent Login')


@app.route('/accounts/agent/register/', methods=['GET', 'POST'])
def register_agent():
    if (request.method == 'POST'):
        email = request.form.get('email')
        name = request.form.get('name').strip()
        password = request.form.get('password')
        print(email)
        secret_key = create_user(name, email, 'r-agt', password)
        values = {"email": email, "name": name, "password": password}
        if(not secret_key):
            return render_template("auth/register.html", user='agent', title='Register Agent', emailExists=True, values=values)

        send_mail.welcome_user(email, name, "agent")

        return redirect(url_for('agent_login'))

    return render_template("auth/register.html", user='agent', title='Register Agent')


@app.route('/agent/dashboard/')
def agent_dashboard():
    cookies = request.cookies.get('key')
    if(not cookies):
        return redirect(url_for('agent_login'))
    if(not is_authenticated(cookies, 'agent')):
        return redirect(url_for('agent_login'))
    agent = agent_details(secret_key=cookies)
    details = dashboard_details(agent_id=agent[0])
    return render_template("dashboard/agent/dashboard.html", agent=agent, title="Dashboard", details=details, page="dashboard")


@app.route('/agent/ticket/<id>/')
def agent_ticket_detail(id):
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'agent')):
        return redirect(url_for('user_login'))
    agent = agent_details(secret_key=cookies)

    ticket = fetch_agent_tickets(agent_id=agent[0], ticket_id=id)

    return render_template("dashboard/agent/ticket.html", agent=agent, ticket=ticket)


@app.route('/agent/tickets/<status>/')
def agent_tickets(status):
    if(status not in ['all', 'pending', 'solved']):
        return render_template('error/404.html', title='Error - 404 Page Not Found', back='/agent/tickets/all/')
    cookies = request.cookies.get('key')
    if(not is_authenticated(cookies, 'agent')):
        return redirect(url_for('agent_login'))
    agent = agent_details(secret_key=cookies)
    if(status == 'all'):
        tickets = fetch_agent_tickets(agent[0])
    else:
        tickets = fetch_agent_tickets(agent_id=agent[0], status=status.title())

    return render_template("dashboard/agent/tickets.html", title=f'{status.title()} Tickets', agent=agent, tickets=tickets, page=status)


@app.route('/tickets/set-status/<id>/<status>/')
def set_status(id, status):
    cookies = request.cookies.get('key')
    is_agent = is_authenticated(cookies, 'agent')
    is_admin = is_authenticated(cookies, 'admin')
    is_solved = False
    if (is_agent):
        if (status not in ['open', 'pending', 'on-hold', 'solved', 'closed']):
            return render_template('error/404.html', title='Error - 404 Page Not Found', back='/agent/tickets/all/')
        status = status.replace('-', ' ').title()
        ticket_detail = set_ticket_status(id,status)
        if (status == "Solved"):
            SendGrid().ticket_solved(ticket_detail["email"], id, ticket_detail["short_description"], ticket_detail["issue"])
        return redirect(request.referrer)
    elif(is_admin):
        if (status not in ['open', 'pending', 'on-hold', 'solved', 'closed']):
            return render_template('error/404.html', title='Error - 404 Page Not Found', back='/admin/tickets/all/')
        status = status.replace('-', ' ').title()
        ticket_detail = set_ticket_status(id, status)
        if(status == "Solved"):
            SendGrid().ticket_solved(ticket_detail["email"], id, ticket_detail["short_description"], ticket_detail["issue"])
        return redirect(url_for('ticket_details', id=id, success="Updated Ticket"))
    else:
        return redirect(url_for('agent_login'))


@app.route('/tickets/set-agent/<id>/<agent_id>/')
def set_agent(id, agent_id):
    cookies = request.cookies.get('key')
    if(not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    set_ticket_agent(id, agent_id)
    user = user_details(ticket_id=id)
    print(user)
    send_mail.agent_assignations(user[2], "", id)
    return redirect(request.referrer)


@app.route('/accounts/admin/login/', methods=['GET', 'POST'])
def admin_login():
    cookies = request.cookies.get('key')
    if (cookies):
        if(is_authenticated(cookies, 'admin')):
            return redirect('/admin/dashboard/')
    if (request.method == 'POST'):
        email = request.form.get('email')
        password = request.form.get('password')
        secret_key = authentication(email, password, 'admin')
        if (not secret_key):
            values = {"email": email, "password": password}
            secret_key = authentication(email, password, 'r-adm')
            if not secret_key:
                return render_template("auth/login.html", user='admin', title='Admin Login', values=values,
                                   error="Incorrect login credentials")

            return render_template("auth/login.html", user='admin', title='Admin Login', values=values,
                                   error="Account Verification Pending")

        response = make_response(redirect('/accounts/admin/login/'))
        response.set_cookie('key', secret_key)
        return response

    return render_template("auth/login.html", user='admin', title='Admin Login')


@app.route('/accounts/admin/register/', methods=['GET', 'POST'])
def register_admin():
    if (request.method == 'POST'):
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        secret_key = create_user(name, email, 'r-adm', password)
        values = {"email": email, "name": name, "password": password}
        if(not secret_key):
            return render_template("auth/register.html", user='admin', title='Register Admin', emailExists=True, values=values)

        send_mail.welcome_user(email, name, "admin")

        return redirect(url_for('admin_login'))

    return render_template("auth/register.html", user='admin', title='Register Admin')


@app.route('/admin/dashboard/')
def admin_dashboard():
    cookies = request.cookies.get('key')
    if(not cookies):
        return redirect(url_for('admin_login'))
    if(not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)
    details = dashboard_details()
    return render_template("dashboard/admin/dashboard.html", admin=admin, title="Dashboard", details=details, page="dashboard")


@app.route('/admin/ticket/<id>/')
def ticket_details(id):
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)

    ticket = fetch_all_tickets(ticket_id=id)
    agents = fetch_all_agents()

    return render_template("dashboard/admin/ticket.html", admin=admin, ticket=ticket, agents=agents, title="Ticket Detail", page="ticket")


@app.route('/admin/tickets/<status>/')
def all_tickets(status):
    success = (request.args.get("success"))
    if(status not in ['all', 'open', 'pending', 'on-hold', 'solved', 'closed']):
        return render_template('error/404.html', title='Error - 404 Page Not Found', back='/agent/tickets/all/')
    cookies = request.cookies.get('key')
    if(not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)
    if(status == 'all'):
        tickets = fetch_all_tickets()
    elif(status == 'on-hold'):
        tickets = fetch_all_tickets(status='On Hold')
    else:
        tickets = fetch_all_tickets(status=status.title())

    return render_template("dashboard/admin/tickets.html", title=f'{status.title()} Tickets', admin=admin, tickets=tickets, page=status, success=success)


@app.route('/admin/agents/all/')
def all_agents():
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)

    agents = fetch_all_agents()
    return render_template("dashboard/admin/all-agent.html", agents=agents, admin=admin, page="all-agent", title="All Agents")


@app.route('/admin/agents/requests/')
def requested_agents():
    success = (request.args.get("success"))
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)
    agents = fetch_requested_users("agent")
    return render_template("dashboard/admin/requested-agent.html", agents=agents, admin=admin, success=success, page="requested-agent", title="Requested Agents")


@app.route('/admin/admins/all/')
def all_admins():
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)
    admins = fetch_requested_users("admin")
    return render_template("dashboard/admin/all-admin.html", admins=admins, admin=admin, page="all-admin", title="All Admins")


@app.route('/admin/admins/requests/')
def requested_admins():
    success = (request.args.get("success"))
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    admin = admin_details(secret_key=cookies)
    admins = fetch_requested_users("r-adm")
    return render_template("dashboard/admin/requested-admin.html", admins=admins, admin=admin, success=success, page="requested-admin", title="Requested Admins")


@app.route('/requests/<role>/<status>/<id>/')
def role_control(role, status, id):
    cookies = request.cookies.get('key')
    if (not is_authenticated(cookies, 'admin')):
        return redirect(url_for('admin_login'))
    email = accept_or_reject(role, status, id)
    print(status)
    if(status=='accept'):
        send_mail.role_verified(email, role)
        return redirect(url_for('requested_'+role+'s', success="Accepted New "+role))
    elif(status=='reject'):
        send_mail.role_rejected(email, role)
        return redirect(url_for('requested_'+role+'s', success="Rejected New "+role))


@app.route('/accounts/logout/')
def logout():
    response = redirect(request.referrer)
    response.set_cookie('key', '', expires=0)
    return response


if __name__ == '__main__':
    app.run(debug=True)