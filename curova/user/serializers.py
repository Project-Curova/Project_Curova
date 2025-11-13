from django.utils.crypto import get_random_string
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from .models import User, Patient, Hospital, Staff
from django.contrib import auth
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    # Remove is_superuser and is_staff from public input
    password = serializers.CharField(max_length=100, write_only=True)

    class Meta:
        model = User
        fields = ('username', 'full_name', 'email', 'dob', 'state', 'country', 'type', 'password')

    def validate(self, attrs):
        username = attrs.get('username', '')
        if not username or not username.isalnum():
            raise serializers.ValidationError("Username must be alphanumeric and not empty.")
        # Ensure type is one of the allowed choices
        if attrs.get('type') not in ['H', 'P', 'S']:
            raise serializers.ValidationError("Invalid user type. Must be one of: H, P, S.")
        return attrs

    def create(self, validated_data):
        request = self.context.get('request', None)

        # Base flags (never set by public users)
        is_staff_flag = False
        is_superuser_flag = False

        # If an authenticated admin is creating users via this endpoint, allow flags
        if request and request.user.is_authenticated and request.user.is_staff:
            # Optional elevated flags via admin-only request data
            is_staff_flag = bool(self.initial_data.get('is_staff', False))
            is_superuser_flag = bool(self.initial_data.get('is_superuser', False))

        # Authorization logic based on type
        user_type = validated_data['type']
        if user_type == 'P':
            is_authorized = True  # patients auto-authorized
        elif user_type == 'H':
            is_authorized = False  # hospitals require admin approval
        else:  # 'S' staff (usually created by hospitals or admins)
            is_authorized = False

        user = User.objects.create_user(
            username=validated_data['username'],
            full_name=validated_data.get('full_name'),
            email=validated_data['email'],
            dob=validated_data.get('dob'),
            state=validated_data.get('state'),
            country=validated_data.get('country'),
            type=user_type,
            password=validated_data['password'],
            is_staff=is_staff_flag,
            is_superuser=is_superuser_flag,
        )
        # Enforce authorization rule after creation
        user.is_authorized = is_authorized
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

        if hospital_user.type != "H":
            raise serializers.ValidationError("Only hospitals can create staff.")

        hospital_profile = Hospital.objects.filter(user=hospital_user).first()
        if not hospital_profile:
            raise serializers.ValidationError("Hospital profile not found for this user.")

        if not hospital_user.is_authorized:
            raise serializers.ValidationError("Hospital must be authorized before creating staff.")

        # Extract user data for staff account
        user_data = validated_data.pop("user")
        staff_user = User.objects.create_user(
            username=user_data["username"],
            email=user_data["email"],
            password=user_data["password"],
            type="S",
        )

        # ✅ Auto‑authorize staff since hospital is authorized
        staff_user.is_authorized = True
        staff_user.save()

        return Staff.objects.create(
            user=staff_user,
            affiliated_hospital=hospital_profile,
            **validated_data
        )
# user/serializers.py

class GoogleAuthSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
