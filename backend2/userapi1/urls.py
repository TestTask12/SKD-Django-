from django.urls import path
from .views import RegisterView,UserListView,LoginAPIView,VerifyEmail,PasswordTokenCheckAPI,RequestPasswordResetEmail,SetNewPasswordAPIView,ChangePasswordView
from rest_framework_simplejwt.views import TokenRefreshView,TokenObtainPairView

urlpatterns = [
    path('',UserListView.as_view()),
    path("register/",RegisterView.as_view(),name="register"),
    path('login/',LoginAPIView.as_view(), name='auth_login'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/',RequestPasswordResetEmail.as_view(), name='request_reset-email'),
    path('password-reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/',SetNewPasswordAPIView.as_view(), name='password-reset-complete')
   
]
