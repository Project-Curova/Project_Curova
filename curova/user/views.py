from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from google.oauth2 import id_token
from google.auth.transport import requests
from rest_framework import generics, status, mixins, permissions, viewsets
from rest_framework.decorators import permission_classes,api_view
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Patient, Hospital
from .serializers import *
from ..curova import settings

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    def post(self,request):
        user= request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)

        is_superuser = serializer.validated_data.get('is_superuser', False)
        is_staff = serializer.validated_data.get('is_staff', False)
        serializer.save()
        user_data = serializer.data
        return Response(user_data, status= status.HTTP_201_CREATED)

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(username=serializer.validated_data['username'])

        if user.is_authorized:
            response_data = serializer.validated_data
            response_data["detail"] = "Logged in Successfully"

            #Generate a refresh token and set it for user
            refresh= RefreshToken.for_user(user)
            user.refresh_token = str(refresh)
            user.save()

            response = Response(response_data, status = status.HTTP_200_OK)
            #response set cokkie
            response.set_cookie('refreshToken', user.refresh_token, secure=True, samesite= 'None')

            return response
        else:
            return  Response({"detail":"Your account needs to be approved by an admin"})


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


class GoogleLoginView(APIView):
    """
    POST /userapi/google-login/
    Body: { "id_token": "<google_id_token>" }
    """
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get("id_token")
        if not token:
            return Response({"detail": "Missing Google ID token"}, status=status.HTTP_400_BAD_REQUEST)

        client_id = settings.GOOGLE_CLIENT_ID
        if not client_id:
            return Response({"detail": "Server misconfiguration: GOOGLE_CLIENT_ID not set"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            idinfo = id_token.verify_oauth2_token(token, requests.Request(), client_id)

            email = idinfo.get("email")
            email_verified = idinfo.get("email_verified", False)
            name = idinfo.get("name", "")

            if not email or not email_verified:
                return Response({"detail": "Email not available or not verified by Google"},
                                status=status.HTTP_400_BAD_REQUEST)

            # Get or create user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "username": email,
                    "full_name": name,
                    "type": "P",   # Default new users are Patients
                }
            )

            if not user.is_authorized:
                return Response(
                    {"detail": "Admin needs to approve your account"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # JWT Tokens
            refresh = RefreshToken.for_user(user)

            # Use your serializer to return consistent user data
            user_data = UserSerializer(user).data

            return Response({
                "detail": "Logged in successfully with Google",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": user_data,
                "new_user": created
            }, status=status.HTTP_200_OK)

        except ValueError:
            return Response({"detail": "Invalid Google token"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"detail": f"Google login failed: {str(e)}"},
                            status=status.HTTP_400_BAD_REQUEST)