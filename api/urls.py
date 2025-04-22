from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .models import Category
from .views import (
    UserViewSet, ProductViewSet, OrderViewSet, CategoryViewSet, upload_image, SubmitShopApplication, RegisterView, LoginView, LogoutView, MyShopView,
    update_shop, delete_shop_picture, ShopDetailView, ShopReviewsAPI, CartViewSet,
    FavoriteViewSet, confirm_shipping, delete_shipping_confirmation, upload_profile_picture
)

# 🌍 Create a router to auto-generate routes for viewsets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'products', ProductViewSet, basename='product')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'cart', CartViewSet, basename='cart')
router.register(r'favorites', FavoriteViewSet, basename='favorite')

urlpatterns = [
    path('', include(router.urls)),  # Includes all routes from the router
    path('upload-image/', upload_image, name="upload-image"),
    path("apply/", SubmitShopApplication.as_view(), name="submit_shop_application"),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path("shops/my-shop/", MyShopView.as_view(), name="my-shop"),
    path("shop/delete_picture/", delete_shop_picture, name="delete-shop-picture"),
    path("shop/update/", update_shop, name="update_shop"),
    path("shops/<int:shop_id>/", ShopDetailView.as_view(), name="get-shop-details"),
    path("shops/<int:shop_id>/reviews/", ShopReviewsAPI.as_view(), name="shop-reviews"),
    path("orders/<int:order_id>/confirm_shipping/", confirm_shipping, name="confirm_shipping"),
    path("orders/<int:order_id>/shipping_confirmation/", delete_shipping_confirmation, name="delete_shipping_confirmation"),
    path("shop/upload_picture/", upload_profile_picture, name="upload_profile_picture"),
]
