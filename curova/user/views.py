from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from google.oauth2 import id_token
from google.auth.transport import requests
from rest_framework.exceptions import PermissionDenied
from .serializers import *
from django.conf import settings
from rest_framework import generics, status, viewsets, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from drf_yasg.utils import swagger_auto_schema
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, Patient, Hospital, Staff, UserProfileOverride
from .serializers import (
    RegisterSerializer, LoginSerializer, LoginResponseSerializer,
    PatientSerializer, HospitalSerializer, StaffSerializer,
    ProfileCompletionToggleSerializer, UserSerializer
)


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "type": user.type,
            "is_authorized": user.is_authorized,
        }, status=201)


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    @swagger_auto_schema(request_body=LoginSerializer, responses={200: LoginResponseSerializer})
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        refresh = RefreshToken.for_user(user)

        if user.type == "P":
            profile_completed = hasattr(user, "patient")
        elif user.type == "H":
            profile_completed = hasattr(user, "hospital")
        elif user.type == "S":
            profile_completed = hasattr(user, "staff")
        else:
            profile_completed = False

        try:
            override = user.userprofileoverride.profile_completed_override
            profile_completed = override
        except UserProfileOverride.DoesNotExist:
            pass

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "username": user.username,
            "email": user.email,
            "user_type": user.type,
            "profile_completed": profile_completed,
            "detail": "Logged in Successfully",
        })


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail':'Logged Out'}, status= status.HTTP_200_OK)

class PasswordResetOTPEmailView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data= request.data)
        serializer.is_valid(raise_exception=True)

        email=serializer.validated_data['email']
        data = serializer.save()

        #generate a uniqure confirm url
        confirmation_url_password_reset = f'http://localhost:8000/reset-password-confirmation/?email={email}'


        #send an email with otp and configuration link
        subject = 'Password Reset OTP and Confirmation Link'
        message = f'Use this OTP to reset your password: {data["otp"]}\n\n'
        message += f'\n\nAlternatively , you can click on the link below to reset your password:\n{confirmation_url_password_reset}'

        from_email = 'webmaster@example.com'
        receipient_list = [email]

        send_mail(subject,message,from_email,receipient_list)

        return Response({'message':'Password reset OTP and confirmation link sent successfully'})


"""class PasswordResetConfirmationView(DetailView):
    model = User
    tem[]"""

class TokenLoginView(APIView):
    def post(self,request):
        username = request.data.get('username')
        token = request.data.get('token')

        user = User.objects.filter(username=username , login_token= token).first()
        if user is not None:
            user.login_token = None
            user.save()
            #Token is correct

            response = Response({"detail":"logged IN"}, status=status.HTTP_200_OK)
            response.set_cookie('refreshToken',user.tokens.refresh, secure=True, samesite='None')

            return response
        else:
            return Response({"detail":"Invalid Token"}, status=status.HTTP_400_BAD_REQUEST)

        

class PatientAPIView(viewsets.ModelViewSet):
    queryset = Patient.objects.all()
    serializer_class = PatientSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        """Attach the logged-in user to the patient profile"""
        serializer.save(user=self.request.user)


class HospitalAPIView(viewsets.ModelViewSet):
    queryset = Hospital.objects.all()
    serializer_class = HospitalSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        """Attach the logged-in user to the patient profile"""
        if self.request.user.is_authorized:
            serializer.save(user=self.request.user)
        else:
            raise serializers.ValidationError("User has not be authenticated by admin")


class StaffAPIView(viewsets.ModelViewSet):
    queryset = Staff.objects.all()
    serializer_class = StaffSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Hospitals only see their staff"""
        if getattr(self, 'swagger_fake_view', False):
            return Staff.objects.none()

        user = self.request.user
        if user.type == "H":
            hospital = Hospital.objects.filter(user=user).first()
            return Staff.objects.filter(affiliated_hospital=hospital)
        elif user.type == "S":
            return Staff.objects.filter(user=user)
        return Staff.objects.none()

    def perform_create(self, serializer):
        if self.request.user.type != "H":
            raise serializers.ValidationError("Only hospitals can create staff.")
        serializer.save()

User = get_user_model()


class GoogleLoginAPIView(APIView):
    @swagger_auto_schema(
        request_body=GoogleAuthSerializer,
        responses={200: "JWT tokens returned"}
    )
    def post(self, request):
        serializer = GoogleAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['token']

        try:
            # Verify token with Google
            idinfo = id_token.verify_oauth2_token(
                token,
                requests.Request(),
                settings.GOOGLE_CLIENT_ID
            )

            # Extract user details
            email = idinfo.get("email")
            full_name = idinfo.get("name")
            google_user_id = idinfo.get("sub")  # unique Google user id

            if not email:
                return Response({"error": "Email not provided by Google"}, status=400)

            # Check if user already exists
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": email.split("@")[0],
                    "full_name": full_name,
                    "type": "P",  # default role (Patient) — you can change this
                    "is_authorized": True,
                    "country": "Unknown",
                    "state": "Unknown"
                }
            )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "full_name": user.full_name,
                    "type": user.type,
                }
            })

        except ValueError:
            return Response({"error": "Invalid Google token"}, status=400)


class ApproveUserAPIView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        user_id = request.data.get("user_id")
        approve = request.data.get("approve", True)
        from .models import User
        user = User.objects.filter(id=user_id).first()
        if not user:
            return Response({"detail": "User not found"}, status=404)
        user.is_authorized = bool(approve)
        user.save()
        return Response({"detail": "User authorization updated", "user_id": user.id, "is_authorized": user.is_authorized})


class PendingUsersListAPIView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        # Fetch all users who are not authorized yet
        pending_users = User.objects.filter(is_authorized=False)
        serializer = UserSerializer(pending_users, many=True)
        return Response(serializer.data)


# -------------------------------
# Hospital ViewSet
# -------------------------------
class HospitalViewSet(viewsets.ModelViewSet):
    queryset = User.objects.filter(type='H', is_authorized=True)
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_update(self, serializer):
        serializer.save()


# -------------------------------
# Patient ViewSet
# -------------------------------
class PatientViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.type == 'P':
            return User.objects.filter(id=user.id)
        return User.objects.none()

    def perform_update(self, serializer):
        serializer.save()


# -------------------------------
# Staff ViewSet
# -------------------------------
class StaffViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        # Hospital sees its staff
        if user.type == 'H':
            return User.objects.filter(type='S', staff__hospital=user.hospital)

        # Staff sees self
        if user.type == 'S':
            return User.objects.filter(id=user.id)

        return User.objects.none()

    def perform_create(self, serializer):
        user = self.request.user

        if user.type != 'H':
            raise PermissionDenied("Only hospitals can create staff")

        serializer.save(
            type='S',
            staff={'hospital': user.hospital}
        )

    def perform_update(self, serializer):
        serializer.save()

class PrimaryHospitalAPIView(generics.RetrieveUpdateAPIView):
    serializer_class = PrimaryHospitalSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        # Ensure only the logged-in patient can access their own record
        user = self.request.user
        if user.type == 'P' and hasattr(user, 'patient'):
            return user.patient
        raise PermissionDenied("Only patients can set a primary hospital.")

class ToggleProfileCompletionAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        request_body=ProfileCompletionToggleSerializer,
        responses={200: "Profile completion override updated"}
    )
    def post(self, request):
        serializer = ProfileCompletionToggleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        value = serializer.validated_data["profile_completed"]

        UserProfileOverride.objects.update_or_create(
            user=request.user,
            defaults={"profile_completed_override": value}
        )

        return Response({
            "detail": "Profile completion override updated",
            "profile_completed": value,
        })
