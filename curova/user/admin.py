from django.contrib import admin
from .models import User, Patient, Hospital, Staff

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = ('full_name', 'email', 'username')

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    search_fields = ('user__full_name', 'user__email')

@admin.register(Hospital)
class HospitalAdmin(admin.ModelAdmin):
    search_fields = ('user__full_name', 'user__email', 'registration_number')

@admin.register(Staff)
class StaffAdmin(admin.ModelAdmin):
    search_fields = ('user__full_name', 'user__email', 'designation')
