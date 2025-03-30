from django.contrib import admin
from .models import Shop, Product, Category, ShippingConfirmation, Order, ShopReview, ShopApproval, OrderItem, Cart, CartItem, Favorite

admin.site.register(Shop)
admin.site.register(Product)
admin.site.register(Category)
admin.site.register(ShippingConfirmation)
admin.site.register(Order)
admin.site.register(ShopReview)
admin.site.register(ShopApproval)
admin.site.register(CartItem)
admin.site.register(Favorite)
admin.site.register(OrderItem)
admin.site.register(Cart)