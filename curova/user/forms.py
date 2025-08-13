""""# forms.py
from django import forms
from django.contrib.auth.models import User

class UserForm(forms.Form):
    username = forms.CharField()
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

from django import forms
from django.contrib.auth.models import User
from .models import Patient

class PatientRegistrationForm(forms.ModelForm):
    # User fields
    username = forms.CharField()
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Patient
        fields = [
            'date_of_birth',
            'gender',
            'address',
            'state',
            'country',
            'patient_id',
            'blood_group',
            'genotype',
            'insurance_provider_name'
        ]

    def save(self, commit=True):
        # Create the user
        user = User.objects.create_user(
            username=self.cleaned_data['username'],
            email=self.cleaned_data['email'],
            password=self.cleaned_data['password']
        )
        # Create the patient and link user
        patient = Patient(
            user=user,
            date_of_birth=self.cleaned_data['date_of_birth'],
            gender=self.cleaned_data['gender'],
            address=self.cleaned_data['address'],
            state=self.cleaned_data['state'],
            country=self.cleaned_data['country'],
            patient_id=self.cleaned_data['patient_id'],
            blood_group=self.cleaned_data['blood_group'],
            genotype=self.cleaned_data['genotype'],
            insurance_provider_name=self.cleaned_data['insurance_provider_name']
        )
        if commit:
            patient.save()
        return patient
"""