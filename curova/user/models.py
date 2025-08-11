# user/models.py

from django.db import models
from django.contrib.auth.models import User

# Patient Profile
class Patient(models.Model):
    GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other')]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    address = models.TextField()
    state = models.CharField(max_length=50)
    country = models.CharField(max_length=50)
    patient_id = models.CharField(max_length=20, unique=True)
    blood_group = models.CharField(max_length=3)
    genotype = models.CharField(max_length=5)
    insurance_provider_name = models.CharField(max_length=100)

    def __str__(self):
        return self.user.username

# Hospital Profile
class Hospital(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    hospital_name = models.CharField(max_length=100)
    registration_no = models.CharField(max_length=50, unique=True)
    location = models.TextField()

    def __str__(self):
        return self.hospital_name

# Staff Profile
class Staff(models.Model):
    GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other')]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    staff_id = models.CharField(max_length=20, unique=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    designation = models.CharField(max_length=100)
    date_of_employment = models.DateField()
    affiliated_hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='staff_members')

    def __str__(self):
        return self.user.username
