# user/admin.py

from django.contrib import admin
from .models import Patient, Hospital, Staff

admin.site.register(Patient)
admin.site.register(Hospital)
admin.site.register(Staff)
