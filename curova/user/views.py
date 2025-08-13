# user/views.py

"""from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Patient, Hospital, Staff
from .serializers import PatientSerializer, HospitalSerializer, StaffSerializer
from .permissions import IsPatient, IsHospital, IsStaff
from .forms import UserForm


# --------- TOKEN HANDLER ---------
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# --------- HTML TEMPLATE VIEWS ---------
def login_user_and_redirect(request, user, role_dashboard):
    tokens = get_tokens_for_user(user)
    request.session['access_token'] = tokens['access']
    request.session['refresh_token'] = tokens['refresh']
    return redirect(role_dashboard)

def patient_register_view(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            serializer = PatientSerializer(data={
                'user': {
                    'username': form.cleaned_data['username'],
                    'email': form.cleaned_data['email'],
                    'password': form.cleaned_data['password']
                }
            })
            if serializer.is_valid():
                serializer.save()
                user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
                return login_user_and_redirect(request, user, 'patient_dashboard')
            else:
                return render(request, 'registration/patient_register.html', {'form': form, 'errors': serializer.errors})
    else:
        form = UserForm()
    return render(request, 'registration/patient_register.html', {'form': form})


def hospital_register_view(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            serializer = HospitalSerializer(data={
                'user': {
                    'username': form.cleaned_data['username'],
                    'email': form.cleaned_data['email'],
                    'password': form.cleaned_data['password']
                }
            })
            if serializer.is_valid():
                serializer.save()
                user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
                return login_user_and_redirect(request, user, 'hospital_dashboard')
            else:
                return render(request, 'registration/hospital_register.html', {'form': form, 'errors': serializer.errors})
    else:
        form = UserForm()
    return render(request, 'registration/hospital_register.html', {'form': form})


@login_required
def staff_register_view(request):
    if not hasattr(request.user, 'hospital'):
        return redirect('login')

    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            serializer = StaffSerializer(data={
                'user': {
                    'username': form.cleaned_data['username'],
                    'email': form.cleaned_data['email'],
                    'password': form.cleaned_data['password']
                },
                'affiliated_hospital': request.user.hospital.id
            })
            if serializer.is_valid():
                serializer.save()
                return redirect('hospital_dashboard')
            else:
                return render(request, 'registration/staff_register.html', {'form': form, 'errors': serializer.errors})
    else:
        form = UserForm()
    return render(request, 'registration/staff_register.html', {'form': form})


@login_required
def patient_dashboard(request):
    return render(request, 'dashboard/patient_dashboard.html')


@login_required
def hospital_dashboard(request):
    return render(request, 'dashboard/hospital_dashboard.html')


@login_required
def staff_dashboard(request):
    return render(request, 'dashboard/staff_dashboard.html')


@login_required
def redirect_dashboard(request):
    if hasattr(request.user, 'patient'):
        return redirect('patient_dashboard')
    elif hasattr(request.user, 'hospital'):
        return redirect('hospital_dashboard')
    elif hasattr(request.user, 'staff'):
        return redirect('staff_dashboard')
    return redirect('login')


# --------- DRF API VIEWS ---------

class PatientRegisterAPIView(APIView):
    def post(self, request):
        serializer = PatientSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Patient registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class HospitalRegisterAPIView(APIView):
    def post(self, request):
        serializer = HospitalSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Hospital registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class StaffRegisterAPIView(APIView):
    def post(self, request):
        serializer = StaffSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Staff registered successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PatientDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated, IsPatient]

    def get(self, request):
        return Response({'message': 'Welcome to Patient Dashboard'})


class HospitalDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated, IsHospital]

    def get(self, request):
        return Response({'message': 'Welcome to Hospital Dashboard'})


class StaffDashboardAPIView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def get(self, request):
        return Response({'message': 'Welcome to Staff Dashboard'})
        # user/views.py

        from django.shortcuts import render, redirect
        from django.contrib.auth import authenticate
        from django.contrib.auth.decorators import login_required
        from django.contrib.auth.models import User
        from rest_framework.views import APIView
        from rest_framework.response import Response
        from rest_framework import status
        from rest_framework.permissions import IsAuthenticated
        from rest_framework_simplejwt.tokens import RefreshToken

        from .models import Patient, Hospital, Staff
        from .serializers import PatientSerializer, HospitalSerializer, StaffSerializer
        from .permissions import IsPatient, IsHospital, IsStaff
        from .forms import UserForm

        # --------- TOKEN HANDLER ---------
        def get_tokens_for_user(user):
            refresh = RefreshToken.for_user(user)
            return {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }

        # --------- HTML TEMPLATE VIEWS ---------
        def login_user_and_redirect(request, user, role_dashboard):
            tokens = get_tokens_for_user(user)
            request.session['access_token'] = tokens['access']
            request.session['refresh_token'] = tokens['refresh']
            return redirect(role_dashboard)

        def patient_register_view(request):
            if request.method == 'POST':
                form = UserForm(request.POST)
                if form.is_valid():
                    serializer = PatientSerializer(data={
                        'user': {
                            'username': form.cleaned_data['username'],
                            'email': form.cleaned_data['email'],
                            'password': form.cleaned_data['password']
                        }
                    })
                    if serializer.is_valid():
                        serializer.save()
                        user = authenticate(username=form.cleaned_data['username'],
                                            password=form.cleaned_data['password'])
                        return login_user_and_redirect(request, user, 'patient_dashboard')
                    else:
                        return render(request, 'registration/patient_register.html',
                                      {'form': form, 'errors': serializer.errors})
            else:
                form = UserForm()
            return render(request, 'registration/patient_register.html', {'form': form})

        def hospital_register_view(request):
            if request.method == 'POST':
                form = UserForm(request.POST)
                if form.is_valid():
                    serializer = HospitalSerializer(data={
                        'user': {
                            'username': form.cleaned_data['username'],
                            'email': form.cleaned_data['email'],
                            'password': form.cleaned_data['password']
                        }
                    })
                    if serializer.is_valid():
                        serializer.save()
                        user = authenticate(username=form.cleaned_data['username'],
                                            password=form.cleaned_data['password'])
                        return login_user_and_redirect(request, user, 'hospital_dashboard')
                    else:
                        return render(request, 'registration/hospital_register.html',
                                      {'form': form, 'errors': serializer.errors})
            else:
                form = UserForm()
            return render(request, 'registration/hospital_register.html', {'form': form})

        @login_required
        def staff_register_view(request):
            if not hasattr(request.user, 'hospital'):
                return redirect('login')

            if request.method == 'POST':
                form = UserForm(request.POST)
                if form.is_valid():
                    serializer = StaffSerializer(data={
                        'user': {
                            'username': form.cleaned_data['username'],
                            'email': form.cleaned_data['email'],
                            'password': form.cleaned_data['password']
                        },
                        'affiliated_hospital': request.user.hospital.id
                    })
                    if serializer.is_valid():
                        serializer.save()
                        return redirect('hospital_dashboard')
                    else:
                        return render(request, 'registration/staff_register.html',
                                      {'form': form, 'errors': serializer.errors})
            else:
                form = UserForm()
            return render(request, 'registration/staff_register.html', {'form': form})

        @login_required
        def patient_dashboard(request):
            return render(request, 'dashboard/patient_dashboard.html')

        @login_required
        def hospital_dashboard(request):
            return render(request, 'dashboard/hospital_dashboard.html')

        @login_required
        def staff_dashboard(request):
            return render(request, 'dashboard/staff_dashboard.html')

        @login_required
        def redirect_dashboard(request):
            if hasattr(request.user, 'patient'):
                return redirect('patient_dashboard')
            elif hasattr(request.user, 'hospital'):
                return redirect('hospital_dashboard')
            elif hasattr(request.user, 'staff'):
                return redirect('staff_dashboard')
            return redirect('login')

        # --------- DRF API VIEWS ---------

        class PatientRegisterAPIView(APIView):
            def post(self, request):
                serializer = PatientSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'Patient registered successfully'}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        class HospitalRegisterAPIView(APIView):
            def post(self, request):
                serializer = HospitalSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'Hospital registered successfully'}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        class StaffRegisterAPIView(APIView):
            def post(self, request):
                serializer = StaffSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({'message': 'Staff registered successfully'}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        class PatientDashboardAPIView(APIView):
            permission_classes = [IsAuthenticated, IsPatient]

            def get(self, request):
                return Response({'message': 'Welcome to Patient Dashboard'})

        class HospitalDashboardAPIView(APIView):
            permission_classes = [IsAuthenticated, IsHospital]

            def get(self, request):
                return Response({'message': 'Welcome to Hospital Dashboard'})

        class StaffDashboardAPIView(APIView):
            permission_classes = [IsAuthenticated, IsStaff]

            def get(self, request):
                return Response({'message': 'Welcome to Staff Dashboard'})
"""
from django.core.mail import send_mail
from django.shortcuts import render
from django.utils.autoreload import raise_last_exception
from django.views.generic import DetailView

from rest_framework import generics,status
from rest_framework.decorators import permission_classes,api_view
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import *

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
    authentication_classes = []
    serializer_class = LogoutSerializer
    @permission_classes([AllowAny])
    #permission_classes = (permissions.IsAuthenticated,)
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