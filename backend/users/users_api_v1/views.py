from rest_framework.response import Response
from rest_framework import status
from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView, RetrieveUpdateDestroyAPIView
from users.users_api_v1.serializers import LoginSerializer, RegisterSerializer, LogoutSerializer, ChangePasswordSerializer, \
    RequestResetPasswordEmailSerializer, SetNewPasswordSerializer, UserSerializer, \
    GenerateOtpSerializer, VerifyOtpSerializer, \
    SetNewPasswordWithPhoneSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import login, logout
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError, force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.template.loader import get_template
from users.utils import Utils
from users.models import User, Role
from users.permissions import IsSuperAdmin, IsCustomer, IsVendorOrSuperAdmin, IsVendor
from rest_framework.filters import SearchFilter, OrderingFilter
from app.settings import BASE_URL
import os
import requests
from app import response_message, utils
from users import response as users_app_response


class RegisterView(GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        try:
            user = request.data
            if User.objects.filter(email=user.get('email')).exists():
                response = {
                    'success': False,
                    'message': users_app_response.user_email_exists,
                    'data': None
                }

                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            if User.objects.filter(phone=user.get('phone')).exists():
                response = {
                    'success': False,
                    'message': users_app_response.user_phone_exists,
                    'data': None
                }

                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data = user)
            serializer.is_valid(raise_exception = True)
            serializer.save()
            user = User.objects.get(email=serializer.data.get('email'))
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            absurl = f'{BASE_URL}/Login?uidb={str(uidb64)}&token={str(token)}'

            context = {
                "fname" : user.first_name,
                "lname": user.last_name,
                "url": absurl
            }

            email_body = get_template('email_templates/verification-mail.html').render(context)
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Activate your account'}
            Utils.send_email(data)

            response = {
                'success': True,
                'message': users_app_response.signup_completed,
                'data': serializer.data
            }

            if serializer.errors:
                response = {
                    'success': True,
                    'message': serializer.errors,
                    'data': None
                }
                return Response(response, status = status.HTTP_200_OK)
        
        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }

            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_201_CREATED)
    
class GenerateVerificationLink(GenericAPIView):
    def post(self, request):
        try:
            user = User.objects.get(email=request.data.get('email'))
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            redirect = request.data.get("route")
            
            if "Shipping" in redirect:
                absurl = f'{BASE_URL}{redirect}?uidb={str(uidb64)}&token={str(token)}'
            elif "Buynow" in redirect:
                absurl = f'{BASE_URL}{redirect}&uidb={str(uidb64)}&token={str(token)}'

            context = {
                "fname" : user.first_name,
                "lname": user.last_name,
                "url": absurl
            }

            email_body = get_template('email_templates/verification-mail.html').render(context)
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Activate your account'}
            Utils.send_email(data)

            response = {
                'success': True,
                'message': users_app_response.sent_verification_link,
                'data': None
            }

        except Exception as e:
            response = {
                'success': False,
                'message': response_message.error_message,
                'error_message': str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_201_CREATED)
    
class VerifyUserTokenView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                resonse = {
                    'success': False, 
                    'message': users_app_response.invalid_token,
                    "error_message": str(e),
                    'data': None
                }
                return Response(resonse, status=status.HTTP_401_UNAUTHORIZED)
            
            user.is_email_verified = True
            user.save()
            refresh = RefreshToken.for_user(user)

            resonse = {
                'success': True, 
                'message': users_app_response.email_verified, 
                'data': {
                    'userId': user.id,
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'userEmail': user.email,
                    'userPhone': user.phone,
                    'userCountryCode': user.country_code,
                    'userRole': user.role.role_name,
                    'userEmailVerified': user.is_email_verified,
                    'userPhoneVerified': user.is_phone_verified,
                    'refreshToken' : str(refresh),
                    'accessToken' : str(refresh.access_token)
                }
            }

        except DjangoUnicodeDecodeError as e:
            if not PasswordResetTokenGenerator().check_token(user):
                resonse = {
                    'success': False, 
                    'message': users_app_response.invalid_token,
                    "error_message": str(e),
                    'data': None
                }
            return Response(resonse, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(resonse, status=status.HTTP_200_OK)
    
class GenerateOtpAPIView(GenericAPIView):
    serializer_class = GenerateOtpSerializer

    def post(self, request):
        try:
            data = request.data
            if data.get('phone') == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_phone,
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data = data)
            serializer.is_valid(raise_exception = True)
            phone = data.get('phone')

            # user = self.request.user
            user = User.objects.filter(phone=phone).first()

            if user.phone == None:
                user.phone = phone

            # if user.country_code == None:
            #     user.country_code = data['country_code']

            otp = Utils.generate_otp(self)
            user.phone_otp = otp
            user.save()
            Utils.send_otp(self, otp, phone)

            response = {
                'success': True,
                'message': users_app_response.otp_sent,
                'data': None
            }

        except Exception as e:
            if e:
                error = False
                if 'users.phone' in str(e):
                    error = True

            response = {
                'success': False,
                'message': users_app_response.user_phone_exists if error else serializer.validated_data,
                'error_message': str(e),
                'data': None
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_201_CREATED)

class AuthVerifyOtpAPIView(GenericAPIView):
    serializer_class = VerifyOtpSerializer
    # permission_classes = [IsAuthenticated, IsCustomer]

    def post(self, request):
        try:
            data = request.data
            if data.get('otp') == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_otp,
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data = data)
            serializer.is_valid(raise_exception = True)
            # user = self.request.user
            user = User.objects.filter(phone=data.get('phone')).first()

            if user.phone_otp == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_new_otp, 
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)

            if user.phone_otp == int(serializer.data.get('otp')):
                user.phone_otp = None
                user.is_phone_verified = True
                user.save()
                refresh = RefreshToken.for_user(user)

                response = {
                    'success': True,
                    'message': users_app_response.phone_verified, 
                    'data': {
                        'userId': user.id,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'userEmail': user.email,
                        'userPhone': user.phone,
                        'userRole': user.role.role_name,
                        # 'userEmailVerified': user.is_email_verified,
                        # 'userPhoneVerified': user.is_phone_verified,
                        'refreshToken' : str(refresh),
                        'accessToken' : str(refresh.access_token)
                    }
                }
            
            elif user.phone_otp != serializer.data.get('otp'):
                response = {
                    'success': False,
                    'message': users_app_response.provide_valid_otp,
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_200_OK)

class VerifyOtpAPIView(GenericAPIView):
    serializer_class = VerifyOtpSerializer

    def post(self, request):
        try:
            data = request.data
            if data.get('otp') == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_otp,
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data = data)
            serializer.is_valid(raise_exception = True)
            user = User.objects.get(phone=serializer.data.get('phone'))

            if user.phone_otp == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_new_otp, 
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)

            if user.phone_otp == int(serializer.data.get('otp')):
                user.phone_otp = None
                user.is_phone_verified = True
                user.save()

                response = {
                    'success': True,
                    'message': users_app_response.phone_verified, 
                    'data': None
                }
            
            elif user.phone_otp != serializer.data.get('otp'):
                response = {
                    'success': False,
                    'message': users_app_response.provide_valid_otp,
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_200_OK)

class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        try:
            session_token = request.GET.get('token')
            data = request.data
            serializer = self.serializer_class(data=data, context={"request": request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
        
            if user is not None:
                refresh = RefreshToken.for_user(user)
                login(request, user)

                if session_token:
                    Utils.manage_cart(self, session_token, user)

                response = {
                    'success': True,
                    'message': users_app_response.user_logged_in,
                    'data': {
                        'userId': user.id,
                        'firstName': user.first_name,
                        'lastName': user.last_name,
                        'userEmail': user.email,
                        'userPhone': user.phone,
                        'userRole': user.role.role_name,
                        'userEmailVerified': user.is_email_verified,
                        'userPhoneVerified': user.is_phone_verified,
                        'refreshToken' : str(refresh),
                        'accessToken' : str(refresh.access_token)
                    }
                }

                return Response(response, status=status.HTTP_200_OK)
        
            response = {
                'success': False,
                'message': response_message.error_message,
                'data': serializer.data
            }
        
        except Exception as e:
            response = {
                'success': False,
                'message': serializer.validated_data,
                'error_message': str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status = status.HTTP_403_FORBIDDEN)
    
class LogoutView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception = True)
            serializer.save()
            logout(request)
            response = {
                'success': True,
                'message': users_app_response.user_logged_out,
                'data': None
            }

        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
    
        return Response(response, status= status.HTTP_200_OK)

class UserDetailsView(RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated, IsCustomer)
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def retrieve(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        response = {
            "success": True,
            "message": users_app_response.user_data,
            "data": serializer.data
        }
        return Response(response, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(request.user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            response = {
                'success': True,
                'message': users_app_response.user_updated,
                'data': serializer.validated_data
            }

        except Exception as e:
            if e:
                error = str(e)
                if error and 'phone' in error:
                    error = users_app_response.user_phone_exists

            response = {
                'success': False,
                'message': serializer.validated_data,
                'error_message': error if error else str(e),
                'data': None
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
    
        return Response(response, status=status.HTTP_200_OK)

class ChangePasswordView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            current_password = serializer.validated_data.get('current_password')
            new_password = serializer.validated_data.get('new_password')
            confirm_password = serializer.validated_data.get('confirm_password')

            if not self.object.check_password(current_password):
                response = {
                    "status": False,
                    "message": users_app_response.provide_valid_current_password,
                    "data": None
                }
                return Response(response, status=status.HTTP_400_BAD_REQUEST)
            
            custom_status = False
            if not new_password:
                message = users_app_response.provide_new_password

            elif not confirm_password:
                message = users_app_response.provide_confirm_password

            elif new_password != confirm_password:
                message = users_app_response.p_c_not_match

            elif current_password == new_password or current_password == confirm_password:
                message = users_app_response.cu_np_same
            
            elif new_password == self.object.check_password(current_password):
                message = users_app_response.cu_np_same
            
            elif new_password == confirm_password and self.object.check_password(current_password):
                self.object.set_password(new_password)
                self.object.save()
                custom_status = True
                message = users_app_response.password_updated

        except Exception as e:
            response = {
                'status': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }

        response = {
            'status': custom_status,
            'message': message,
            'data': None
        }

        return Response(response, status=status.HTTP_200_OK)

class RequestPasswordResetEmailView(GenericAPIView):
    serializer_class = RequestResetPasswordEmailSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(force_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                absurl = f'{BASE_URL}/NewPassword?uidb={str(uidb64)}&token={str(token)}'

                context = {
                    "fname" : user.first_name,
                    "lname": user.last_name,
                    "url": absurl
                }

                email_body = get_template('email_templates/forgot-password.html').render(context)
                data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}
                Utils.send_email(data)

                response = {
                    'success': True,
                    'message': users_app_response.password_reset_link, 
                    'data': None
                }

            else:
                response = {
                    'success': False,
                    'message': users_app_response.provide_registered_email, 
                    'data': None
                }
        
        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status=status.HTTP_200_OK)

class PasswordTokenCheckView(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': users_app_response.generete_new_reset_link}, status=status.HTTP_401_UNAUTHORIZED)
            
            resonse = {
                'success': True, 
                'message': users_app_response.valid_credentials, 
                'data': {
                    'uidb64': uidb64, 
                    'token': token
                }
            }

        except DjangoUnicodeDecodeError as e:
            if not PasswordResetTokenGenerator().check_token(user):
                resonse = {
                    'success': False, 
                    'message': users_app_response.generete_new_reset_link, 
                    'error_message': str(e),
                    'data': None
                }
            return Response(resonse, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(resonse, status=status.HTTP_200_OK)

class SetNewPasswordView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        try:
            if request.data.get('token') == None or request.data.get('uidb64') == None:
                response = {
                    'success': False,
                    'message': users_app_response.generete_new_reset_link, 
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            response = {
                'success': True,
                'message': users_app_response.password_updated,
                'data': None
            }
        
        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status=status.HTTP_200_OK)

class RestePasswordWithPhoneAPIView(GenericAPIView):
    serializer_class = SetNewPasswordWithPhoneSerializer

    def patch(self, request):
        try:
            if request.data.get('phone') == None:
                response = {
                    'success': False,
                    'message': users_app_response.provide_registered_phone, 
                    'data': None
                }
                return Response(response, status = status.HTTP_400_BAD_REQUEST)
            
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            response = {
                'success': True,
                'message': users_app_response.password_updated,
                'data': None
            }
        
        except Exception as e:
            response = {
                'success': False,
                "message": response_message.error_message,
                "error_message": str(e),
                'data': None
            }
            return Response(response, status = status.HTTP_400_BAD_REQUEST)
        
        return Response(response, status=status.HTTP_200_OK)
