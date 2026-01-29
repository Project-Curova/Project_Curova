from django.shortcuts import render
from rest_framework import viewsets, permissions
from rest_framework.exceptions import PermissionDenied
from .models import Break, Holiday, Overtime, ShiftChangeRequest, Shift, StaffShift
from .serializers import (
    ShiftSerializer,
    StaffShiftSerializer,
    BreakSerializer,
    HolidaySerializer,
    OvertimeSerializer,
    ShiftChangeRequestSerializer
)


class HospitalShiftViewSet(viewsets.ModelViewSet):
    serializer_class = ShiftSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'hospital'):
            return Shift.objects.filter(hospital=user.hospital)
        return Shift.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if not hasattr(user, 'hospital'):
            raise PermissionDenied("Only hospitals can create shifts.")
        serializer.save(hospital=user.hospital)


class StaffShiftAssignmentViewSet(viewsets.ModelViewSet):
    serializer_class = StaffShiftSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'hospital'):
            return StaffShift.objects.filter(staff__hospital=user.hospital)
        return StaffShift.objects.none()


class StaffBreakViewSet(viewsets.ModelViewSet):
    serializer_class = BreakSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'staff'):
            return Break.objects.filter(staff=user.staff)
        return Break.objects.none()

    def perform_create(self, serializer):
        serializer.save(staff=self.request.user.staff)


class StaffHolidayViewSet(viewsets.ModelViewSet):
    serializer_class = HolidaySerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'staff'):
            return Holiday.objects.filter(staff=user.staff)
        return Holiday.objects.none()

    def perform_create(self, serializer):
        serializer.save(staff=self.request.user.staff)


class StaffOvertimeViewSet(viewsets.ModelViewSet):
    serializer_class = OvertimeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'staff'):
            return Overtime.objects.filter(staff=user.staff)
        return Overtime.objects.none()

    def perform_create(self, serializer):
        serializer.save(staff=self.request.user.staff)


class ShiftChangeRequestViewSet(viewsets.ModelViewSet):
    serializer_class = ShiftChangeRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'staff'):
            return ShiftChangeRequest.objects.filter(staff=user.staff)
        return ShiftChangeRequest.objects.none()

    def perform_create(self, serializer):
        serializer.save(staff=self.request.user.staff)
