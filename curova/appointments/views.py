from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied

from .models import Appointment
from .serializers import (
    AppointmentSerializer,
    AppointmentCreateSerializer,
    HospitalAppointmentUpdateSerializer,
    StaffAppointmentUpdateSerializer,
)


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
    - Patient:
        - POST /appointments/  (create)
        - GET  /appointments/  (list own)
    - Hospital:
        - GET  /appointments/                      (list for hospital)
        - PATCH /appointments/{id}/hospital-update/ (approve, assign staff, reschedule)
    - Staff:
        - GET  /appointments/                      (list assigned)
        - PATCH /appointments/{id}/staff-update/   (ongoing/done)
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

            status = self.request.query_params.get('status')
            if status:
                qs = qs.filter(status=status)

            return qs

        if hasattr(user, 'staff'):
            qs = Appointment.objects.filter(staff=user.staff)

            status = self.request.query_params.get('status')
            date = self.request.query_params.get('date')

            if status:
                qs = qs.filter(status=status)
            if date:
                qs = qs.filter(requested_date=date)

            return qs

        return Appointment.objects.none()

    def get_serializer_class(self):
        if self.action == 'create':
            return AppointmentCreateSerializer
        if self.action == 'hospital_update':
            return HospitalAppointmentUpdateSerializer
        if self.action == 'staff_update':
            return StaffAppointmentUpdateSerializer
        return AppointmentSerializer

    # -------------------------
    # STEP 4: Hospital update
    # -------------------------
    @action(
        detail=True,
        methods=['patch'],
        url_path='hospital-update',
        permission_classes=[permissions.IsAuthenticated, IsPatientOrHospitalOrStaff],
    )
    def hospital_update(self, request, pk=None):
        appointment = self.get_object()
        user = request.user

        # Only hospitals can use this
        if not hasattr(user, 'hospital') or appointment.hospital_id != user.hospital.id:
            raise PermissionDenied("Only the hospital owning this appointment can perform this action.")

        serializer = self.get_serializer(appointment, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(AppointmentSerializer(appointment).data)

    # -------------------------
    # STEP 4: Staff update
    # -------------------------
    @action(
        detail=True,
        methods=['patch'],
        url_path='staff-update',
        permission_classes=[permissions.IsAuthenticated, IsPatientOrHospitalOrStaff],
    )
    def staff_update(self, request, pk=None):
        appointment = self.get_object()
        user = request.user

        # Only assigned staff can use this
        if not hasattr(user, 'staff') or appointment.staff_id != user.staff.id:
            raise PermissionDenied("Only the assigned staff can update this appointment.")

        serializer = self.get_serializer(appointment, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(AppointmentSerializer(appointment).data)
