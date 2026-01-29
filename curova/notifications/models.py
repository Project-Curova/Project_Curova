# Create your models here.
from django.db import models
from django.conf import settings


class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('appointment_request', 'Appointment Request'),
        ('appointment_confirmed', 'Appointment Confirmed'),
        ('appointment_completed', 'Appointment Completed'),
        ('staff_assigned', 'Staff Assigned'),
        ('shift_update', 'Shift Update'),
        ('holiday_approved', 'Holiday Approved'),
        ('overtime_approved', 'Overtime Approved'),
    ]

    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    notification_type = models.CharField(
        max_length=50,
        choices=NOTIFICATION_TYPES
    )
    message = models.TextField()
    is_read = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.notification_type} → {self.recipient}"
