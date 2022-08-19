from django.urls import path, include
from rest_framework.routers import DefaultRouter

from st_common_data.auth.views import Auth0ViewSet

router = DefaultRouter()
router.register(r'auth0', Auth0ViewSet, basename='auth0')

urlpatterns = [
    path('', include(router.urls)),
]
