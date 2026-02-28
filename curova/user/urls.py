from django.urls import path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegisterView, LoginAPIView, LogoutAPIView,
    PatientAPIView, HospitalAPIView, StaffAPIView,
    GoogleLoginAPIView, ApproveUserAPIView,
    PendingUsersListAPIView, PrimaryHospitalAPIView,
    ToggleProfileCompletionAPIView
)

router = DefaultRouter()
router.register(r'patients', PatientAPIView, basename='patients')
router.register(r'hospitals', HospitalAPIView, basename='hospitals')
router.register(r'staff', StaffAPIView, basename='staff')

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('login/', LoginAPIView.as_view()),
    path('logout/', LogoutAPIView.as_view()),
    path('api/token/refresh/', TokenRefreshView.as_view()),
    path('auth/google/', GoogleLoginAPIView.as_view()),

    path('approve/', ApproveUserAPIView.as_view()),
    path('pending/', PendingUsersListAPIView.as_view()),

    path('primary-hospital/', PrimaryHospitalAPIView.as_view()),
    path("profile-completion/toggle/", ToggleProfileCompletionAPIView.as_view()),
]

urlpatterns += router.urls
