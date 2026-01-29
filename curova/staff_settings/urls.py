from rest_framework.routers import DefaultRouter
from .views import (
    HospitalShiftViewSet,
    StaffShiftAssignmentViewSet,
    StaffBreakViewSet,
    StaffHolidayViewSet,
    StaffOvertimeViewSet,
    ShiftChangeRequestViewSet
)

router = DefaultRouter()
router.register(r'shifts', HospitalShiftViewSet, basename='shifts')
router.register(r'staff-shifts', StaffShiftAssignmentViewSet, basename='staff-shifts')
router.register(r'breaks', StaffBreakViewSet, basename='breaks')
router.register(r'holidays', StaffHolidayViewSet, basename='holidays')
router.register(r'overtime', StaffOvertimeViewSet, basename='overtime')
router.register(r'shift-change', ShiftChangeRequestViewSet, basename='shift-change')

urlpatterns = router.urls
