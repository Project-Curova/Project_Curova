from django.contrib import admin
from .models import Appointment

@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'patient', 'hospital', 'staff',
        'requested_date', 'requested_time',
        'communication_method', 'status', 'confirmed_time',
        'created_at'
    )
    list_filter = ('hospital', 'status', 'communication_method', 'requested_date')
    search_fields = (
        'patient__user__full_name',
        'hospital__user__full_name',
        'staff__user__full_name',
        'symptoms',
    )
    autocomplete_fields = ('patient', 'hospital', 'staff')

