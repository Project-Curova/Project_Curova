from django.db import router
from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework.urls import app_name

from . import views


from rest_framework_simplejwt.views import (
TokenRefreshView
)
from .views import PatientAPIView

router = DefaultRouter()
router.register(r'patients', PatientAPIView, basename='patients')


urlpatterns = [
    path('register/', views.RegisterView.as_view(),name='register'),
    path('login/', views.LoginAPIView.as_view(),name='login'),
    path('logout/', views.LogoutAPIView.as_view(),name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(),name='token_refresh'),

]

urlpatterns += router.urls