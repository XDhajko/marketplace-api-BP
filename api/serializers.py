import base64

from django.contrib.auth import authenticate, get_user_model
from django.core.files.base import ContentFile
from rest_framework import serializers
from .models import Product, Order, OrderItem, Category, Shop, ShopReview, CartItem, Cart, Favorite, \
    ShippingConfirmation

User = get_user_model()

# -----------------------
# User Serializer
# -----------------------
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

# -----------------------
# Category Serializer
# -----------------------
class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = "__all__"

# -----------------------
# Product Serializer
# -----------------------

class ProductCardSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required=False)
    class Meta:
        model = Product
        fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source="category.name", read_only=True)
    image = serializers.ImageField(required= False)
    shop_products = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = '__all__'

    def to_internal_value(self, data):
        """Handles base64 image input without breaking"""
        if "image" in data and isinstance(data["image"], str) and data["image"].startswith("data:image"):
            format, imgstr = data["image"].split(";base64,")
            ext = format.split("/")[-1]
            data["image"] = ContentFile(base64.b64decode(imgstr), name=f"upload.{ext}")
        return super().to_internal_value(data)

    def get_shop_products(self, obj):
        if not obj.shop:
            return []

        other_products = obj.shop.products.exclude(id=obj.id)[:4]
        return ProductCardSerializer(other_products, many=True).data

# Used to display each order item
class OrderItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source="product.name", read_only=True)
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = ['id', 'product', 'product_name', 'quantity', 'price', 'created_at']


class ShippingConfirmationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ShippingConfirmation
        fields = "__all__"
        read_only_fields = ["order", "shop"]


class OrderSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    items = OrderItemSerializer(many=True, read_only=True)
    shipping_confirmation = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = '__all__'

    def get_shipping_confirmation(self, obj):
        request = self.context.get('request')
        if not request or not hasattr(request.user, 'shop'):
            return None

        shop = request.user.shop
        confirmation = obj.shipping_confirmations.filter(shop=shop).first()
        if confirmation:
            return ShippingConfirmationSerializer(confirmation).data
        return None

    def update(self, instance, validated_data):
        # Only allow status updates through PATCH
        status = validated_data.get('status', None)
        if status:
            instance.status = status
            instance.save()
        return instance


# Minimal serializer to receive items from frontend
class SimpleOrderItemSerializer(serializers.Serializer):
    product = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1)


# For creating a new order from checkout
class OrderCreateSerializer(serializers.Serializer):
    items = SimpleOrderItemSerializer(many=True)
    shipping_address = serializers.CharField(required=True)
    shipping_city = serializers.CharField(required=True)
    shipping_country = serializers.CharField(required=True)
    shipping_postal_code = serializers.CharField(required=True)
    full_name = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=False, allow_blank=True)
    payment_method = serializers.CharField(required=True)

    def validate_items(self, value):
        if not value:
            raise serializers.ValidationError("At least one item is required.")
        return value


class RegisterSerializer(serializers.ModelSerializer):
    """
    Handles user registration with strong validation.
    """
    password = serializers.CharField(write_only=True, min_length=8, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("An account with this email already exists.")
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Password must contain at least one number.")
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not any(char.islower() for char in value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        return value

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    """
    Handles user authentication and validation.
    """
    username = serializers.CharField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, data):
        username = data.get("username")
        password = data.get("password")

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError("Invalid username or password.", code="authorization")
        else:
            raise serializers.ValidationError("Both username and password are required.", code="authorization")

        data["user"] = user
        return data


class ShopSerializer(serializers.ModelSerializer):
    approval_status = serializers.SerializerMethodField()

    class Meta:
        model = Shop
        fields = '__all__'

    def get_approval_status(self, obj):
        try:
            return obj.approval_request.status
        except:
            return None


class ShopReviewSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)  # Returns username
    shop = serializers.PrimaryKeyRelatedField(read_only=True)  # No need to send `shop` in the request

    class Meta:
        model = ShopReview
        fields = ["id", "shop", "user", "rating", "text", "created_at"]
        read_only_fields = ["user", "shop", "created_at"]

class CartItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)
    product_discount = serializers.DecimalField(source='product.discount', max_digits=4, decimal_places=2, read_only=True)
    product_image = serializers.ImageField(source='product.image', read_only=True)
    shop_id = serializers.IntegerField(source='product.shop.id', read_only=True)
    shop_image = serializers.ImageField(source='product.shop.profile_picture', read_only=True)
    shop_name = serializers.CharField(source='product.shop.shop_name', read_only=True)
    category = serializers.CharField(source='product.category.name', read_only=True)

    class Meta:
        model = CartItem
        fields = ['id', 'product', 'quantity', 'product_name', 'product_price', 'product_discount', 'product_image', 'shop_id', 'shop_image', 'shop_name', 'category']


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True)

    class Meta:
        model = Cart
        fields = ['id', 'user', 'created_at', 'items']


class AddToCartSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1, default=1)

class FavoriteSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_image = serializers.ImageField(source='product.image', read_only=True)
    product_price = serializers.DecimalField(source='product.price', max_digits=10, decimal_places=2, read_only=True)
    product_discount = serializers.DecimalField(source='product.discount', max_digits=3, decimal_places=2, read_only=True)

    class Meta:
        model = Favorite
        fields = ['id', 'product', 'product_name', 'product_image', 'product_price', 'product_discount']


