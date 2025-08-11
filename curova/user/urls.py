from django.urls import path
from . import views

urlpatterns = [
    # Template Views
    path('register/patient/', views.patient_register_view, name='patient_register'),
    path('register/hospital/', views.hospital_register_view, name='hospital_register'),
    path('register/staff/', views.staff_register_view, name='staff_register'),

    path('dashboard/patient/', views.patient_dashboard, name='patient_dashboard'),
    path('dashboard/hospital/', views.hospital_dashboard, name='hospital_dashboard'),
    path('dashboard/staff/', views.staff_dashboard, name='staff_dashboard'),

    path('redirect-dashboard/', views.redirect_dashboard, name='redirect_dashboard'),

    # API Views
    path('api/register/patient/', views.PatientRegisterAPIView.as_view(), name='api_patient_register'),
    path('api/register/hospital/', views.HospitalRegisterAPIView.as_view(), name='api_hospital_register'),
    path('api/register/staff/', views.StaffRegisterAPIView.as_view(), name='api_staff_register'),

    path('api/dashboard/patient/', views.PatientDashboardAPIView.as_view(), name='api_patient_dashboard'),
    path('api/dashboard/hospital/', views.HospitalDashboardAPIView.as_view(), name='api_hospital_dashboard'),
    path('api/dashboard/staff/', views.StaffDashboardAPIView.as_view(), name='api_staff_dashboard'),
]
