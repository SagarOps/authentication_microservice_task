from django.urls import path
from users.users_api_v1.views import LoginView, LogoutView, RegisterView, VerifyUserTokenView, \
    UserDetailsView, ChangePasswordView, RequestPasswordResetEmailView, PasswordTokenCheckView, SetNewPasswordView, \
    GenerateVerificationLink, GenerateOtpAPIView, VerifyOtpAPIView, \
    AuthVerifyOtpAPIView, RestePasswordWithPhoneAPIView
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('login', LoginView.as_view(), name ='login-user'),
    path('verification-link', GenerateVerificationLink.as_view(), name='generate-verification-link'),
    path('generate-otp', GenerateOtpAPIView.as_view(), name='generate-otp'),
    path('login-phone-otp', AuthVerifyOtpAPIView.as_view(), name='login-phone-otp'),
    path('verify-otp', VerifyOtpAPIView.as_view(), name='verify-otp'),
    path('login/refresh', jwt_views.TokenRefreshView.as_view(), name ='token-refresh'),
    path('logout', LogoutView.as_view(), name = 'logout-user'),
    path('register', RegisterView.as_view(), name ='register-user'),
    path('verify-user/<uidb64>/<token>', VerifyUserTokenView.as_view(), name='verify-user'),
    path('users/<int:id>', UserDetailsView.as_view(), name = 'user-details'),
    path('change-password', ChangePasswordView.as_view(),name='change-password'),
    path('forgot-password', RequestPasswordResetEmailView.as_view(), name='request-reset-email'),
    path('forgot-password-with-otp', RestePasswordWithPhoneAPIView.as_view(), name='password-reset-with-otp'),
    path('forgot-password/<uidb64>/<token>', PasswordTokenCheckView.as_view(), name='password-reset-confirm'),
    path('forgot-password/reset-complete', SetNewPasswordView.as_view(), name='password-reset-complete'),
]