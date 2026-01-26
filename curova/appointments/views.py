from rest_framework import viewsets, permissions
from .models import Appointment
from .serializers import AppointmentSerializer, AppointmentCreateSerializer


class IsPatientOrHospitalOrStaff(permissions.BasePermission):
    """
    Allows access only to users related to the appointment.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user = request.user

        if hasattr(user, 'patient') and obj.patient_id == user.patient.id:
            return True
        if hasattr(user, 'hospital') and obj.hospital_id == user.hospital.id:
            return True
        if hasattr(user, 'staff') and obj.staff_id == user.staff.id:
            return True

        return user.is_staff


class AppointmentViewSet(viewsets.ModelViewSet):
    """
    Unified Appointment ViewSet:
    - GET: list/retrieve appointments based on user role
    - POST: patient creates appointment (uses primary hospital)
    - PATCH/PUT: reserved for Step 4 (hospital/staff updates)
    """

    permission_classes = [IsPatientOrHospitalOrStaff]

    def get_queryset(self):
        # Swagger safety
        if getattr(self, 'swagger_fake_view', False):
            return Appointment.objects.none()

        user = self.request.user

        if hasattr(user, 'patient'):
            return Appointment.objects.filter(patient=user.patient)

        if hasattr(user, 'hospital'):
            qs = Appointment.objects.filter(hospital=user.hospital)

            # Optional hospital filters
            status = self.request.query_params.get('status')
            if status:
                qs = qs.filter(status=status)

            return qs

        if hasattr(user, 'staff'):
            qs = Appointment.objects.filter(staff=user.staff)

            # Optional staff filters
            status = self.request.query_params.get('status')
            date = self.request.query_params.get('date')

            if status:
                qs = qs.filter(status=status)
            if date:
                qs = qs.filter(requested_date=date)

            return qs

        return Appointment.objects.none()

    def get_serializer_class(self):
        # Use special serializer only when creating
        if self.action == 'create':
            return AppointmentCreateSerializer
        return AppointmentSerializer
