from django.db import models

# Create your models here.


class Shift(models.Model):
    hospital = models.ForeignKey(
        'users.Hospital',
        on_delete=models.CASCADE,
        related_name='shifts'
    )
    name = models.CharField(max_length=100)
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_continuous = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.start_time} - {self.end_time})"

class StaffShift(models.Model):
    staff = models.ForeignKey(
        'users.Staff',
        on_delete=models.CASCADE,
        related_name='assigned_shifts'
    )
    shift = models.ForeignKey(
        Shift,
        on_delete=models.CASCADE,
        related_name='staff_members'
    )
    effective_from = models.DateField()
    effective_to = models.DateField(null=True, blank=True)

    class Meta:
        unique_together = ('staff', 'shift', 'effective_from')

class Break(models.Model):
    staff = models.ForeignKey(
        'users.Staff',
        on_delete=models.CASCADE,
        related_name='breaks'
    )
    date = models.DateField()
    start_time = models.TimeField()
    end_time = models.TimeField()
    is_paid = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

class Holiday(models.Model):
    staff = models.ForeignKey(
        'users.Staff',
        on_delete=models.CASCADE,
        related_name='holidays'
    )
    start_date = models.DateField()
    end_date = models.DateField()
    approved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

class Overtime(models.Model):
    staff = models.ForeignKey(
        'users.Staff',
        on_delete=models.CASCADE,
        related_name='overtimes'
    )
    date = models.DateField()
    hours = models.DecimalField(max_digits=4, decimal_places=2)
    approved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

class ShiftChangeRequest(models.Model):
    staff = models.ForeignKey(
        'users.Staff',
        on_delete=models.CASCADE,
        related_name='shift_change_requests'
    )
    from_shift = models.ForeignKey(
        Shift,
        on_delete=models.CASCADE,
        related_name='change_from'
    )
    to_shift = models.ForeignKey(
        Shift,
        on_delete=models.CASCADE,
        related_name='change_to'
    )
    date = models.DateField()
    approved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
