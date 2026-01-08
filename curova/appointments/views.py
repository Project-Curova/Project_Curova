from rest_framework import viewsets, permissions, generics
from .models import Appointment
from .serializers import AppointmentSerializer, AppointmentCreateSerializer

class IsPatientOrHospitalOrStaff(permissions.BasePermission):
    """
    Placeholder permission. Replace with your role checks.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user = request.user
        # Allow if user belongs to the appointment context
        if hasattr(user, 'patient') and obj.patient_id == user.patient.id:
            return True
        if hasattr(user, 'hospital') and obj.hospital_id == user.hospital.id:
            return True
        if hasattr(user, 'staff') and obj.staff_id == user.staff.id:
            return True
        # Admins can view
        return user.is_staff

class AppointmentViewSet(viewsets.ModelViewSet):
    queryset = Appointment.objects.select_related('patient', 'hospital', 'staff')
    serializer_class = AppointmentSerializer
    permission_classes = [IsPatientOrHospitalOrStaff]


# Patients: view their own appointments
class PatientAppointmentListAPIView(generics.ListAPIView):
    serializer_class = AppointmentSerializer
    #permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.type == 'P' and hasattr(user, 'patient'):
            return Appointment.objects.filter(patient=user.patient)
        return Appointment.objects.none()

# Hospitals: view appointments for their hospital
class HospitalAppointmentListAPIView(generics.ListAPIView):
    serializer_class = AppointmentSerializer
    #permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.type == 'H' and hasattr(user, 'hospital'):
            qs = Appointment.objects.filter(hospital=user.hospital)
            # Optional filters
            status = self.request.query_params.get('status')
            if status:
                qs = qs.filter(status=status)
            return qs
        return Appointment.objects.none()

# Staff: view appointments assigned to them
class StaffAppointmentListAPIView(generics.ListAPIView):
    serializer_class = AppointmentSerializer
    #permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.type == 'S' and hasattr(user, 'staff'):
            qs = Appointment.objects.filter(staff=user.staff)
            # Optional filters
            status = self.request.query_params.get('status')
            date = self.request.query_params.get('date')
            if status:
                qs = qs.filter(status=status)
            if date:
                qs = qs.filter(requested_date=date)
            return qs
        return Appointment.objects.none()

# Patient: create appointment (auto‑uses primary hospital)
class AppointmentCreateAPIView(generics.CreateAPIView):
    serializer_class = AppointmentCreateSerializer
    #permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save()