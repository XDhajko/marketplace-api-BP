from django.urls import path
from . import views

urlpatterns = [
    path("approve-shop/<int:shop_id>/", views.approve_shop),
    path("reject-shop/<int:shop_id>/", views.reject_shop),
    path("reports/user/<str:username>/", views.user_report),
    path("reports/shop/<int:shop_id>/", views.shop_report),
    path("reports/user-activity/<str:username>/", views.generate_auth_report),
    path("stats/shop-status/", views.shop_status_stats),
    path("audit/logins/", views.login_events),
]
