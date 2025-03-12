from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .models import Category
from .views import (
    UserViewSet, CustomerViewSet, ProductViewSet, OrderViewSet, CategoryViewSet, upload_image, SubmitShopApplication,
    ApproveShop, RejectShop, RegisterView, LoginView, LogoutView, MyShopView,
    update_shop, upload_shop_picture, delete_shop_picture,
)

# 🌍 Create a router to auto-generate routes for viewsets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'customers', CustomerViewSet, basename='customer')
router.register(r'products', ProductViewSet, basename='product')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'categories', CategoryViewSet, basename='category')

urlpatterns = [
    path('', include(router.urls)),  # Includes all routes from the router
    path('upload-image', upload_image, name="upload-image"),
    path("apply/", SubmitShopApplication.as_view(), name="submit_shop_application"),
    path("approve/<int:shop_id>/", ApproveShop.as_view(), name="approve_shop"),
    path("reject/<int:shop_id>/", RejectShop.as_view(), name="reject_shop"),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("shops/my-shop/", MyShopView.as_view(), name="my-shop"),
    path("shop/upload_picture", upload_shop_picture, name="upload-shop-picture"),
    path("shop/delete_picture", delete_shop_picture, name="delete-shop-picture"),
    path("shop/update", update_shop, name="update_shop"),
]
