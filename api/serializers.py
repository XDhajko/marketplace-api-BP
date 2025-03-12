import base64

from django.contrib.auth import authenticate, get_user_model
from django.core.files.base import ContentFile
from rest_framework import serializers
from .models import Product, Customer, Order, OrderItem, Category, Shop

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
class ProductSerializer(serializers.ModelSerializer):
    image = serializers.ImageField(required= False)

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


# -----------------------
# Customer Serializer
# -----------------------
class CustomerSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Customer
        fields = '__all__'


# -----------------------
# Order Item Serializer (Nested Inside Order)
# -----------------------
class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = OrderItem
        fields = '__all__'


# -----------------------
# Order Serializer
# -----------------------
class OrderSerializer(serializers.ModelSerializer):
    customer = CustomerSerializer(read_only=True)
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = '__all__'


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
    class Meta:
        model = Shop
        fields = '__all__'