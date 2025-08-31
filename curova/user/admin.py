# user/admin.py

from django.contrib import admin
from  .models import  *

admin.site.register(User)
admin.site.register(Patient)
admin.site.register(Hospital)
admin.site.register(Staff)