from django.urls import path, include

urlpatterns = [
    path('', include('auditing_service.urls')),
]
