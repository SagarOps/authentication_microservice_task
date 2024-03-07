from rest_framework.serializers import ModelSerializer, Serializer, CharField, EmailField, ImageField, FileField
from users.models import User, Role
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed
from app import utils, response_message
from users import response as users_app_response
import uuid

class UserSerializer(ModelSerializer):

    class Meta:
        model = User
        fields = ['id', 'first_name','last_name', 'phone', 'email', 'password', 'role','is_phone_verified', 'is_email_verified', 'is_active', 'created_at']
        
    def to_representation(self, instance):
        data =  super().to_representation(instance)
        data['created_at'] = utils.date_formatting(data['created_at'])
        return data
    
    def update(self, instance, validated_data):
        phone = validated_data.get('phone')
        if phone and instance.phone != phone:
            instance.is_phone_verified = False
        return super().update(instance, validated_data)
    
class GenerateOtpSerializer(Serializer):
    phone = CharField(label='phone number', required=True)

class VerifyOtpSerializer(Serializer):
    otp = CharField(label='otp', required=True)
    phone = CharField(label='phone number', required=True)

class RegisterSerializer(ModelSerializer):
    password = CharField(label='Password', write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = CharField(label='Confirm Password', write_only=True, required=True, style={'input_type': 'password'})
    role = CharField(default="Customer")
    phone = CharField(label="phone", required=True)
    
    class Meta:
        model = User
        fields = ['id', 'first_name','last_name', 'phone', 'email', 'password', 'confirm_password', 'role']

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.pop('confirm_password')

        if 'role' in data:
            data['role'] = Role.objects.get(role_name=data['role'])

        if password != confirm_password:
            message = users_app_response.password_confirm_must_same
            return message
        
        return super().validate(data)

    def create(self, validated_data):
        if 'role' not in validated_data:
            validated_data['role'] = Role.objects.get(role_name="Customer")
        return User.objects.create_user(**validated_data)
    

class LoginSerializer(ModelSerializer):
    email = EmailField(max_length = 255, min_length = 3, required=False)
    phone = CharField(max_length = 15, required=False)
    password = CharField(max_length = 16, min_length = 6, write_only = True,  style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ['email', 'phone', 'password']

    def validate(self, data):
        email = data.get('email', None)
        phone = data.get('phone', None)
        password = data.get('password')
        
        if email:
            user = authenticate(email=email, password=password)
        elif phone:
            user = authenticate(phone=phone, password=password)
        
        if user and not user.is_active:
            message = users_app_response.account_disabled
            return message

        if not user:
            message = users_app_response.check_credentials
            return message

        data['user'] = user
        return data

class LogoutSerializer(Serializer):
    refresh = CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        
        except TokenError:
            self.fail(response_message.error_message)

class ChangePasswordSerializer(Serializer):
    current_password = CharField(write_only=True)
    new_password = CharField(write_only=True)
    confirm_password = CharField(write_only=True)

class RequestResetPasswordEmailSerializer(Serializer):
    email = EmailField(min_length=2, required=True)

    class Meta:
        fields = ['email']
        
class SetNewPasswordSerializer(Serializer):
    password = CharField(min_length=6, max_length=68, write_only=True)
    token = CharField(min_length=1, write_only=True)
    uidb64 = CharField(min_length=1, write_only=True)
    
    class Meta:
        fields = ['password', 'token', 'uidb64']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            if token == None or uidb64 == None:
                raise AuthenticationFailed(users_app_response.generete_new_reset_link,401)
            
            uuid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uuid)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed(users_app_response.generete_new_reset_link,401)
            user.set_password(password)
            user.save()
            
        except Exception as e:
            raise AuthenticationFailed(users_app_response.generete_new_reset_link, 401) from e
        
        return super().validate(attrs)
    
class SetNewPasswordWithPhoneSerializer(Serializer):
    password = CharField(min_length=6, max_length=68, write_only=True)
    phone = CharField(min_length=1, required=True)
    
    class Meta:
        fields = ['password', 'phone']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            phone = attrs.get('phone')
            
            if phone == None:
                raise AuthenticationFailed(users_app_response.provide_registered_phone, 401)
            
            user = User.objects.get(phone=phone)
            user.set_password(password)
            user.save()
            
        except Exception as e:
            raise AuthenticationFailed(response_message.error_message, 401) from e
        
        return super().validate(attrs)
