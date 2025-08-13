"""from rest_framework.permissions import BasePermission

class IsPatient(BasePermission):
    def has_permission(self, request, view):
        return hasattr(request.user, 'patient')

class IsHospital(BasePermission):
    def has_permission(self, request, view):
        return hasattr(request.user, 'hospital')

class IsStaff(BasePermission):
    def has_permission(self, request, view):
        return hasattr(request.user, 'staff')"""
