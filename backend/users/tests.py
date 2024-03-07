from django.test import TestCase
import json
from django.urls import include, path, reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient, URLPatternsTestCase
from users.models import User, Role

# Create your tests here.
class UserTest(APITestCase, URLPatternsTestCase):
    """ Test module for User """

    urlpatterns = [
        path('', include('users.users_api_v1.urls')),
    ]

    def setUp(self):
        role = Role.objects.create(role_name='Customer')
        role_admin = Role.objects.create(role_name='Admin')
        self.user1 = User.objects.create_user(
            email='test1@test.com',
            phone=91234567810,
            password='test@123',
            role=role
        )

        self.admin = User.objects.create_superuser(
            email='admin@test.com',
            phone=91234567811,
            password='admin@123',
            role=role_admin
        )

    def test_login(self):
        """ Test if a user can login and get a JWT response token """
        
        url = reverse('login-user')
        data = {
            'email': 'test1@test.com',
            'password': 'test@123'
        }
        response = self.client.post(url, data)
        response_data = json.loads(response.content)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response_data['success'], True)
        self.assertTrue('accessToken' in response_data['data'])

    def test_list_all_users_as_admin(self):
        """ Test fetching all users. Restricted to admins """
        
        url = reverse('login-user')
        data = {'email': 'admin@test.com', 'password': 'admin@123'}
        response = self.client.post(url, data)
        login_response_data = json.loads(response.content)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('accessToken' in login_response_data['data'])
        token = login_response_data['data']['accessToken']

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION='JWT ' + token)
        response = client.get(reverse('users'))
        response_data = json.loads(response.content)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.count(), len(response_data['data']))
