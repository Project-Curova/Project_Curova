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

class HospitalAppointmentUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ['status', 'confirmed_time', 'staff']

    def validate(self, attrs):
        instance = self.instance
        new_status = attrs.get('status', instance.status)

        # Hospital can only move: new -> pending
        if instance.status == 'new' and new_status not in ['pending']:
            raise serializers.ValidationError("Hospital can only move 'new' appointments to 'pending'.")

        # Prevent hospital from marking as done
        if new_status == 'done':
            raise serializers.ValidationError("Hospital cannot mark appointments as 'done'.")

        return attrs


class StaffAppointmentUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ['status']

    def validate(self, attrs):
        instance = self.instance
        new_status = attrs.get('status', instance.status)

        # Staff can move: pending -> ongoing, ongoing -> done
        if instance.status == 'pending' and new_status != 'ongoing':
            raise serializers.ValidationError("From 'pending', staff can only move to 'ongoing'.")
        if instance.status == 'ongoing' and new_status != 'done':
            raise serializers.ValidationError("From 'ongoing', staff can only move to 'done'.")
        if instance.status not in ['pending', 'ongoing']:
            raise serializers.ValidationError("Staff can only update 'pending' or 'ongoing' appointments.")

        return attrs
