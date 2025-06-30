from django.urls import path
from .views import MyTokenObtainPairView, api_register  # <-- check this

from rest_framework_simplejwt.views import TokenRefreshView

from .views import MyTokenObtainPairView, api_register, active_users
from django.urls import path
from .views import user_profile, change_password


urlpatterns = [
    path('api/token/', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', api_register, name='api_register'),
    path('api/active-users/', active_users, name='active_users'),
    path('api/profile/', user_profile),
    path('api/change-password/', change_password),
]