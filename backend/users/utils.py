''' send_mail function is for sending an email '''
from celery import shared_task
from django.core.mail import EmailMessage
import os
import random
import threading
from twilio.rest import Client

from_email = os.getenv('EMAIL_HOST_USERNAME')

class Utils:
    @staticmethod
    def send_email(data):
        # send_email_task.delay(data)
        email = EmailMessage(
                subject=data['email_subject'], 
                body=data['email_body'], 
                from_email=str(from_email),
                to=[data['to_email']]
            )
        email.content_subtype ="html"
        if data.get('file_name'):
            email.attach_file(data['file_name'])
        thread = threading.Thread(target=email.send)
        thread.start()

    def generate_otp(self):
        otp = random.randint(100000, 999999)
        return otp
    
    def send_otp(self, otp, phone):
        print("OTP - ", otp)
        # account_sid = os.getenv('TWILIO_ACCOUNT_SID')
        # auth_token = os.getenv('TWILIO_AUTH_TOKEN')
        # client = Client(account_sid, auth_token)
        # client.messages.create(body= f"Login OTP is: {otp}", from_='+', to=f'{phone}')
        return True