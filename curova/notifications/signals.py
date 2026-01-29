from django.db.models.signals import post_save
from django.dispatch import receiver
from appointments.models import Appointment
from .services import create_notification
from staff_settings.models import Holiday, Overtime

@receiver(post_save, sender=Appointment)
def appointment_created(sender, instance, created, **kwargs):
    if created:
        create_notification(
            instance.hospital.user,
            'appointment_request',
            'A new appointment request has been submitted.'
        )
@receiver(post_save, sender=Appointment)
def staff_assigned(sender, instance, **kwargs):
    if instance.staff:
        create_notification(
            instance.staff.user,
            'staff_assigned',
            'You have been assigned to a new appointment.'
        )

@receiver(post_save, sender=Appointment)
def appointment_completed(sender, instance, **kwargs):
    if instance.status == 'done':
        create_notification(
            instance.patient.user,
            'appointment_completed',
            'Your appointment has been completed.'
        )


@receiver(post_save, sender=Appointment)
def appointment_approved(sender, instance, **kwargs):
    if instance.status == 'pending' and instance.confirmed_time:
        create_notification(
            instance.patient.user,
            'appointment_confirmed',
            'Your appointment has been confirmed by the hospital.'
        )





@receiver(post_save, sender=Holiday)
def holiday_approved(sender, instance, **kwargs):
    if instance.approved:
        create_notification(
            instance.staff.user,
            'holiday_approved',
            'Your holiday request has been approved.'
        )

@receiver(post_save, sender=Overtime)
def overtime_approved(sender, instance, **kwargs):
    if instance.approved:
        create_notification(
            instance.staff.user,
            'overtime_approved',
            'Your overtime request has been approved.'
        )


