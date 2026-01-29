from rest_framework import serializers
from .models import (
    Shift,
    StaffShift,
    Break,
    Holiday,
    Overtime,
    ShiftChangeRequest
)


class ShiftSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shift
        fields = '__all__'
        read_only_fields = ['hospital', 'created_at']


class StaffShiftSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaffShift
        fields = '__all__'


class BreakSerializer(serializers.ModelSerializer):
    class Meta:
        model = Break
        fields = '__all__'
        read_only_fields = ['staff', 'created_at']


class HolidaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Holiday
        fields = '__all__'
        read_only_fields = ['staff', 'approved', 'created_at']


class OvertimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Overtime
        fields = '__all__'
        read_only_fields = ['staff', 'approved', 'created_at']


class ShiftChangeRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShiftChangeRequest
        fields = '__all__'
        read_only_fields = ['staff', 'approved', 'created_at']
