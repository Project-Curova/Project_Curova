from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AppointmentViewSet, PatientAppointmentListAPIView, HospitalAppointmentListAPIView, \
    StaffAppointmentListAPIView, AppointmentCreateAPIView

router = DefaultRouter()
router.register(r'appointments', AppointmentViewSet, basename='appointment')

urlpatterns = [
    path('', include(router.urls)),
path('appointments/patient/', PatientAppointmentListAPIView.as_view(), name='patient-appointments'),
    path('appointments/hospital/', HospitalAppointmentListAPIView.as_view(), name='hospital-appointments'),
    path('appointments/staff/', StaffAppointmentListAPIView.as_view(), name='staff-appointments'),
    path('appointments/create/', AppointmentCreateAPIView.as_view(), name='appointment-create'),
]
