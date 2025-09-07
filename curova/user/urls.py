from django.db import router
from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework.urls import app_name

from . import views


from rest_framework_simplejwt.views import (
TokenRefreshView
)
from .views import PatientAPIView, HospitalAPIView, StaffAPIView, GoogleLoginAPIView

router = DefaultRouter()
router.register(r'patient', PatientAPIView, basename='patient')
router.register(r'hospital', HospitalAPIView, basename='hospital')
router.register(r'staff', StaffAPIView, basename='staff')

urlpatterns = [
    path('register/', views.RegisterView.as_view(),name='register'),
    path('login/', views.LoginAPIView.as_view(),name='login'),
    path('logout/', views.LogoutAPIView.as_view(),name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(),name='token_refresh'),
    path("auth/google/", GoogleLoginAPIView.as_view(), name="google-login"),

]

urlpatterns += router.urls