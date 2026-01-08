from rest_framework import serializers
from .models import Appointment


class AppointmentSerializer(serializers.ModelSerializer):
    requested_datetime = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = Appointment
        fields = [
            'id', 'patient', 'hospital', 'staff',
            'symptoms', 'requested_date', 'requested_time',
            'communication_method', 'confirmed_time',
            'status', 'requested_datetime',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['status', 'created_at', 'updated_at']

    def get_requested_datetime(self, obj):
        return obj.requested_datetime()


class AppointmentCreateSerializer(AppointmentSerializer):
    class Meta(AppointmentSerializer.Meta):
        # Inherit everything, but hospital becomes read‑only (auto-filled)
        read_only_fields = AppointmentSerializer.Meta.read_only_fields + ['hospital']

    def create(self, validated_data):
        user = self.context['request'].user

        # Only patients can create appointments
        if user.type == 'P' and hasattr(user, 'patient'):
            patient = user.patient
            validated_data['patient'] = patient

            # Auto‑assign primary hospital
            if patient.primary_hospital:
                validated_data['hospital'] = patient.primary_hospital
            else:
                raise serializers.ValidationError(
                    "No primary hospital set. Please select a hospital first."
                )

        return super().create(validated_data)
