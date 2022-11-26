from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

class SendGrid:

    def __init__(self):
        self.sg = SendGridAPIClient('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')

    def send_mail(self, to, template_id, template_data):
        message = Mail(
            from_email='poonkawin8484@gmail.com',
            to_emails='{}'.format(to)
        )
        message.template_id = template_id
        message.dynamic_template_data = template_data
        self.sg.send(message)

    def send_otp(self, to, otp):
        template_id = "d-92287bf7af6e45a7873a498b6151cf45"
        template_data = {
            "otp": otp,
        }
        self.send_mail(to, template_id, template_data)

    def welcome_user(self, to, name, role=None):
        if(role):
            template_id = "d-ce6def207fc34dce9f83e0f9c317e41f"
            template_data = {
                "name": name,
                "user": role
            }
        else:
            template_id = "d-0cbee97b109d497e852e9d8060d4adca"
            template_data = {
                "name":name,
                "url":"http://localhost:5000/user/accounts/login/"
            }
        self.send_mail(to, template_id, template_data)

    def role_verified(self, to, role):
        template_id = "d-a4f3db73bc5c4c98a14ce7fef2439d34"
        template_data = {
            "role":role,
        }
        self.send_mail(to, template_id, template_data)

    def role_rejected(self, to, role):
        template_id = "d-a636aa1911dd49579bd0f923d93cfec3"
        template_data = {
            "role": role
        }
        self.send_mail(to, template_id, template_data)

    def new_ticket(self, to, ticket_id, short_description, issue):
        template_id = "d-58b36168b058488fad016a1f974ad0db"
        template_data = {
            "ticket_id":ticket_id,
            "short_description":short_description,
            "issue":issue,
            "url": "http://localhost:5000/user/ticket/{}/".format(ticket_id)
        }
        self.send_mail(to, template_id, template_data)

    def ticket_solved(self, to, ticket_id, short_description, issue):
        template_id = "d-426788f9f47e4b53ace5ff14d1daed6c"
        template_data = {
            "ticket_id":ticket_id,
            "short_description":short_description,
            "issue":issue,
            "url": "http://localhost:5000/user/ticket/{}/".format(ticket_id)
        }
        self.send_mail(to, template_id, template_data)

    def agent_assignations(self, to, agent, ticket_id):
        template_id = "d-e22a32fcd2c24785aa00537c025f5c1e"
        template_data = {
            "agent": agent,
            "ticket_id": ticket_id,
            "url": "http://localhost:5000/user/ticket/{}/".format(ticket_id)
        }
        self.send_mail(to, template_id, template_data)