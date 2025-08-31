from django.utils.crypto import get_random_string
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import User, Patient, Hospital, Staff
from django.contrib import auth
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100)
    is_superuser = serializers.BooleanField(default=False)
    is_staff = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ('username', 'full_name','email','dob','state','country','type', 'password','is_superuser','is_staff')

    def validate(self, attrs):
        email = attrs.get('email','')
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError(
                self.default_error_messages)
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            username= validated_data['username'],
            full_name= validated_data['full_name'],
            email= validated_data['email'],
            dob= validated_data['dob'],
            state= validated_data['state'],
            country= validated_data['country'],
            type= validated_data['type'],
            password= validated_data['password'],
            is_superuser= validated_data['is_superuser'],
            is_staff= validated_data['is_staff'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=1)
    tokens = serializers.SerializerMethodField()
    def get_tokens(self, obj):
        user = User.objects.get(username=obj['username'])
        return user.tokens
    class Meta:
        model= User
        fields = ['password','username','tokens']

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        #if username exists
        if not User.objects.filter(username=username).exists():
            raise AuthenticationFailed('invalid username, try again')

        user = auth.authenticate(username= username, password=password)

        #Check if password is correct
        if user is None:
            raise AuthenticationFailed('Invalid Password, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')

        if not user.is_authorized:
            raise AuthenticationFailed('Admin needs to approve your account')

        return {
            'email':user.email,
            'username':user.username,
            'tokens':user.tokens()
        }

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            raise serializers.ValidationError(str(e))
            # self fail bad tokens

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, value):
        user = User.objects.filter(email=value).first()
        if user is None:
            raise serializers.ValidationError("No user found with this email.")
        return value


    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email = email)
        #generate a 6 digit OTP
        otp = get_random_string(length=6, allowed_chars='1234567890')
        user.login_token = otp
        user.save()
        return {'user':user , 'otp': otp}
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "full_name", "dob", "type", "country", "state"]
        read_only_fields = ["id", "type", "email", "username"]


class PatientSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Patient
        fields = [
           "id", "user", "date_of_birth", "gender", "address",
            "state", "country", "patient_id", "blood_group",
            "genotype", "insurance_provider_name"
        ]
        read_only_fields = ["id", "patient_id"]

class HospitalSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Hospital
        fields = [
           "id", "user", "hospital_name", "registration_no", "location" ]
        read_only_fields = ["id"]

class StaffSerializer(serializers.ModelSerializer):
    # Nested user info for staff login account
    user = RegisterSerializer(write_only=True)
    affiliated_hospital = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Staff
        fields = [
            "id", "user", "staff_id", "gender", "designation",
            "date_of_employment", "affiliated_hospital"
        ]
        read_only_fields = ["id", "affiliated_hospital"]

    def create(self, validated_data):
        request = self.context.get("request")
        hospital_user = request.user

        # ✅ only hospital can create staff
        if hospital_user.type != "H":
            raise serializers.ValidationError("Only hospitals can create staff.")

        hospital_profile = Hospital.objects.filter(user=hospital_user).first()
        if not hospital_profile:
            raise serializers.ValidationError("Hospital profile not found for this user.")

        # ✅ extract user data from request
        user_data = validated_data.pop("user")
        staff_user = User.objects.create_user(
            username=user_data["username"],
            email=user_data["email"],
            password=user_data["password"],
            type="S",
        )

        # ✅ create staff profile linked to hospital
        return Staff.objects.create(
            user=staff_user,
            affiliated_hospital=hospital_profile,
            **validated_data
        )