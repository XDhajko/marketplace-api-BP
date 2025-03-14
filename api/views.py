import os
from rest_framework.authtoken.models import Token
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import update_last_login
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, login, logout
from rest_framework.views import APIView
from PIL import Image

from .models import Product, Customer, Order, OrderItem, Category, ShopApproval, Shop
from .serializers import (
    UserSerializer, ProductSerializer,
    CustomerSerializer, OrderSerializer, OrderItemSerializer, CategorySerializer, RegisterSerializer, LoginSerializer,
    ShopSerializer
)
from lxml import etree

User = get_user_model()

# ------------------------------
# 1️⃣ USER REGISTRATION & AUTHENTICATION
# ------------------------------
class UserViewSet(viewsets.ModelViewSet):
    """
    Handles user registration and retrieval.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

class CategoryViewSet(viewsets.ModelViewSet):
    """
    Handles categories creation and retrieval.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]

# ------------------------------
# 2️⃣ CUSTOMER REGISTRATION & PROFILE
# ------------------------------
class CustomerViewSet(viewsets.ModelViewSet):
    """
    Allows customers to register and view their profile.
    """
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Customer.objects.filter(user=self.request.user)


class ProductViewSet(viewsets.ModelViewSet):
    """
    Allows approved suppliers to manage their products.
    Customers can view all available products.
    """
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [AllowAny]  # Anyone can view products

    @action(detail=False, methods=["get"])
    def my_shop(self, request):
        """Alternative way: Explicit /products/my_shop/ endpoint"""
        user = request.user
        if not hasattr(user, 'shop'):
            return Response({"error": "User does not own a shop"}, status=400)

        products = Product.objects.filter(shop=user.shop)
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        user = request.user
        if not hasattr(user, "shop"):
            return Response({"error": "Only shop owners can add products."}, status=status.HTTP_403_FORBIDDEN)

        request.data["shop"] = user.shop.id  # Assign product to the shop
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        user = request.user
        instance = self.get_object()
        if instance.shop.user != user:
            return Response({"error": "You can only edit your own products."}, status=status.HTTP_403_FORBIDDEN)

        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        user = request.user
        instance = self.get_object()
        if instance.shop.user != user:
            return Response({"error": "You can only delete your own products."}, status=status.HTTP_403_FORBIDDEN)

        return super().destroy(request, *args, **kwargs)


# ------------------------------
# 6️⃣ ORDERING SYSTEM
# ------------------------------
class OrderViewSet(viewsets.ModelViewSet):
    """
    Allows customers to place orders and view their order history.
    """
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Limits customers to their own orders.
        """
        if self.request.user.role == "customer":
            customer = get_object_or_404(Customer, user=self.request.user)
            return Order.objects.filter(customer=customer)
        return Order.objects.none()

    def create(self, request, *args, **kwargs):
        """
        Creates an order with multiple products.
        """
        customer = get_object_or_404(Customer, user=request.user)
        order_data = request.data
        order_items = order_data.get("items", [])

        # Calculate total price
        total_price = sum(
            Product.objects.get(id=item["product"]).price * item["quantity"]
            for item in order_items
        )

        order = Order.objects.create(customer=customer, total_price=total_price)

        for item in order_items:
            product = get_object_or_404(Product, id=item["product"])
            OrderItem.objects.create(order=order, product=product, quantity=item["quantity"], price=product.price)

        return Response({"message": "Order placed successfully"}, status=status.HTTP_201_CREATED)

@csrf_exempt
def upload_image(request):
    if request.method == 'POST' and request.FILES.get('image'):
        image_file = request.FILES['image']
        file_path = os.path.join('uploads', image_file.name)

        # Save the file using Django's default storage system
        file_name = default_storage.save(file_path, ContentFile(image_file.read()))
        file_url = request.build_absolute_uri(default_storage.url(file_name))

        return JsonResponse({'image_url': file_url})

    return JsonResponse({'error': 'No image uploaded'}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class SubmitShopApplication(APIView):
    """
    Handles the submission of shop applications with vulnerable XML parsing (XXE).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        xml_data = request.body.decode("utf-8")  # Decode bytes to string

        try:
            # ⚠️ XXE Vulnerability: Enabling entity expansion
            parser = etree.XMLParser(resolve_entities=True)  # XXE enabled
            root = etree.fromstring(xml_data, parser=parser)

            # Extract shop data from XML elements (XXE will be reflected if injected)
            shop_name = root.find("shopName").text if root.find("shopName") is not None else "Unnamed Shop"
            selected_country = root.find("selectedCountry").text if root.find("selectedCountry") is not None else ""
            selected_language = root.find("selectedLanguage").text if root.find("selectedLanguage") is not None else ""
            selected_currency = root.find("selectedCurrency").text if root.find("selectedCurrency") is not None else ""
            bank_name = root.find("bankName").text if root.find("bankName") is not None else ""
            iban = root.find("iban").text if root.find("iban") is not None else ""
            swift_bic = root.find("swiftBic").text if root.find("swiftBic") is not None else ""
            bank_location = root.find("bankLocation").text if root.find("bankLocation") is not None else ""
            business_name = root.find("businessName").text if root.find("businessName") is not None else ""
            tax_id = root.find("taxId").text if root.find("taxId") is not None else ""
            billing_address = root.find("billingAddress").text if root.find("billingAddress") is not None else ""
            billing_country = root.find("billingCountry").text if root.find("billingCountry") is not None else ""

            # Create the shop (XXE payload inside shop_name will be stored)
            shop = Shop.objects.create(
                user=request.user,
                shop_name=shop_name,  # ⚠️ This may contain XXE output
                selected_country=selected_country,
                selected_language=selected_language,
                selected_currency=selected_currency,
                bank_name=bank_name,
                iban=iban,
                swift_bic=swift_bic,
                bank_location=bank_location,
                business_name=business_name,
                tax_id=tax_id,
                billing_address=billing_address,
                billing_country=billing_country,
                is_active=False
            )

            # Process Products
            products_xml = root.find("Products")
            if products_xml is not None:
                for product in products_xml.findall("Product"):
                    title = product.find("title").text if product.find("title") is not None else "Unnamed Product"
                    description = product.find("description").text if product.find("description") is not None else ""
                    category_name = product.find("category").text if product.find("category") is not None else "Uncategorized"
                    price = product.find("price").text if product.find("price") is not None else "0.00"
                    quantity = product.find("quantity").text if product.find("quantity") is not None else "1"
                    image_url = product.find("image").text if product.find("image") is not None else ""

                    # Create or get category
                    category, _ = Category.objects.get_or_create(name=category_name)

                    # Create product in the database
                    Product.objects.create(
                        shop=shop,
                        name=title,
                        description=description,
                        price=price,
                        stock=int(quantity),
                        category=category,
                        is_active=False,  # Products are inactive until shop is approved
                    )

            # Store raw XML to simulate realistic XXE attack processing
            approval = ShopApproval.objects.create(shop=shop, products_xml=xml_data)

            return JsonResponse(
                {
                    "message": "Your shop was created and is waiting for approval.",
                    "shop_id": shop.id,
                    "shop_name": shop.shop_name  # ⚠️ If XXE exploited, output appears here
                }
            )

        except Exception as e:
            return JsonResponse({"error": "Invalid XML format", "details": str(e)}, status=400)




@method_decorator(login_required, name='dispatch')
class ApproveShop(APIView):
    """
    Handles shop approval by admins.
    """

    def post(self, request, shop_id):
        if not request.user.is_staff:
            return JsonResponse({"error": "Permission denied"}, status=403)

        approval = get_object_or_404(ShopApproval, shop_id=shop_id)

        if approval.status != "pending":
            return JsonResponse({"error": "Shop is already processed"}, status=400)

        # Activate the shop
        approval.shop.is_active = True
        approval.shop.save()

        # Activate all products under this shop
        Product.objects.filter(shop=approval.shop).update(is_active=True)

        # Mark approval as completed
        approval.status = "approved"
        approval.save()

        return JsonResponse({"message": f"Shop {approval.shop.shop_name} has been approved."})



@method_decorator(login_required, name='dispatch')
class RejectShop(APIView):
    """
    Handles shop rejection by admins.
    """

    def post(self, request, shop_id):
        if not request.user.is_staff:
            return JsonResponse({"error": "Permission denied"}, status=403)

        approval = get_object_or_404(ShopApproval, shop_id=shop_id)

        if approval.status != "pending":
            return JsonResponse({"error": "Shop is already processed"}, status=400)

        approval.reject()  # Keep the shop inactive

        return JsonResponse({"message": f"Shop {approval.shop.shop_name} has been rejected."})


class RegisterView(APIView):
    """
    Handles user registration and automatic login upon success.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)

            login(request, user)  # Log the user in
            return Response(
                {"token": token.key, "user": {"id": user.id, "username": user.username, "email": user.email}},
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    Handles user authentication and token retrieval.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            token, created = Token.objects.get_or_create(user=user)
            update_last_login(None, user)  # Update last login
            login(request, user)  # Log user in

            return Response(
                {"token": token.key, "user": {"id": user.id, "username": user.username, "email": user.email}},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    Logout user by deleting the token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.auth.delete()  # Delete token before logout
        logout(request)
        return Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)


class MyShopView(APIView):
    """Retrieve the shop that belongs to the currently logged-in user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            shop = Shop.objects.get(user=request.user)
            serializer = ShopSerializer(shop)
            return Response(serializer.data, status=200)
        except Shop.DoesNotExist:
            return Response({"error": "Shop not found"}, status=404)


ALLOWED_IMAGE_TYPES = (".jpg", ".jpeg", ".png", ".svg")

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@csrf_exempt
def upload_shop_picture(request):
    """Handles shop profile picture uploads (XXE in SVG, safe for images)."""
    user_shop = request.user.shop
    file = request.FILES.get("profile_picture")

    if not file or not file.name.lower().endswith(ALLOWED_IMAGE_TYPES):
        return JsonResponse({"error": "Invalid file type"}, status=400)

    # Save file first
    file_path = default_storage.save(f"profile_pictures/{file.name}", file)
    full_path = os.path.join(default_storage.location, file_path)

    # Process SVG with XXE vulnerability
    if file.name.lower().endswith(".svg"):
        try:
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.parse(full_path, parser)
        except etree.XMLSyntaxError:
            return JsonResponse({"error": "Invalid SVG file"}, status=400)

    # Process JPG/PNG securely (ensure they are valid images)
    else:
        try:
            with Image.open(full_path) as img:
                img.verify()  # Validate image integrity
        except Exception:
            os.remove(full_path)  # Delete invalid image
            return JsonResponse({"error": "Invalid image file"}, status=400)

    # Save the profile picture to the shop model
    user_shop.profile_picture = file_path
    user_shop.save()

    return JsonResponse({"message": "Profile picture uploaded", "url": user_shop.profile_picture.url})

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_shop_picture(request):
    """Deletes the shop's profile picture."""
    user_shop = request.user.shop

    if user_shop.profile_picture:
        file_path = user_shop.profile_picture.path
        default_storage.delete(file_path)  # Delete the file from storage
        user_shop.profile_picture = None
        user_shop.save()

    return JsonResponse({"message": "Profile picture deleted successfully"})


@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def update_shop(request):
    """Allows shop owners to update their shop details."""
    try:
        shop = request.user.shop  # Ensure the user has a shop
    except Shop.DoesNotExist:
        return Response({"error": "You do not own a shop."}, status=status.HTTP_403_FORBIDDEN)

    serializer = ShopSerializer(shop, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
