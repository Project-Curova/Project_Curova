from django.db import models
from django.utils import timezone
# Assuming these models live in the 'user' app
from user.models import Patient, Hospital, Staff

class Appointment(models.Model):
    COMMUNICATION_CHOICES = [
        ('onsite', 'Onsite'),
        ('video', 'Video call'),
        ('voice', 'Voice call'),
    ]

    STATUS_CHOICES = [
        ('new', 'New'),           # created by patient, not yet processed by hospital
        ('pending', 'Pending'),   # awaiting hospital confirmation
        ('ongoing', 'Ongoing'),   # confirmed, not yet completed
        ('done', 'Done'),         # completed
    ]

    # Core links
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='appointments')
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='appointments')
    staff = models.ForeignKey(Staff, on_delete=models.SET_NULL, null=True, blank=True, related_name='appointments')

    # Patient’s request details
    symptoms = models.TextField()
    requested_date = models.DateField()
    requested_time = models.TimeField()
    communication_method = models.CharField(max_length=10, choices=COMMUNICATION_CHOICES)

    # Hospital’s decision
    confirmed_time = models.DateTimeField(null=True, blank=True)

    # Lifecycle
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='new')

    # Meta
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['hospital', 'status']),
            models.Index(fields=['patient', 'requested_date']),
        ]

    def __str__(self):
        who = f'{self.patient} @ {self.hospital}'
        when = f'{self.requested_date} {self.requested_time}'
        return f'Appointment({who} | {when} | status={self.status})'

    def requested_datetime(self):
        """
        Convenience: combine requested_date + requested_time into a timezone-aware datetime.
        """
        dt = timezone.datetime.combine(self.requested_date, self.requested_time)
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt, timezone.get_current_timezone())
        return dt

    def clean(self):
        """
        Optional validations for consistency.
        """
        # If staff is assigned, they must belong to the same hospital
        if self.staff and self.staff.hospital_id != self.hospital_id:
            from django.core.exceptions import ValidationError
            raise ValidationError('Assigned staff must belong to the same hospital.')

        # Confirmed time (if set) should not be in the past relative to creation (soft check)
        if self.confirmed_time and self.confirmed_time < timezone.now():
            from django.core.exceptions import ValidationError
            raise ValidationError('Confirmed time cannot be set in the past.')
