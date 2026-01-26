from django.urls import path
from rest_framework.routers import DefaultRouter

from rest_framework_simplejwt.views import TokenRefreshView

from . import views
from .views import (
    PatientAPIView,
    HospitalAPIView,
    StaffAPIView,
    GoogleLoginAPIView,
    ApproveUserAPIView,
    PendingUsersListAPIView,
    PrimaryHospitalAPIView,
)

router = DefaultRouter()

# Profile / User ViewSets
router.register(r'patients', PatientAPIView, basename='patients')
router.register(r'hospitals', HospitalAPIView, basename='hospitals')
router.register(r'staff', StaffAPIView, basename='staff')

urlpatterns = [
    # Auth
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginAPIView.as_view(), name='login'),
    path('logout/', views.LogoutAPIView.as_view(), name='logout'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/google/', GoogleLoginAPIView.as_view(), name='google-login'),

    # Admin / Approval
    path('approve/', ApproveUserAPIView.as_view(), name='approve-user'),
    path('pending/', PendingUsersListAPIView.as_view(), name='pending-users'),

    # Patient Primary Hospital
    path('primary-hospital/', PrimaryHospitalAPIView.as_view(), name='primary-hospital'),
]

urlpatterns += router.urls
