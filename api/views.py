import os
import subprocess
import tempfile
from datetime import datetime
from PIL import Image
import platform
from io import BytesIO
from pathlib import Path

from drf_spectacular.openapi import AutoSchema
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
from rest_framework.decorators import action, api_view, permission_classes, schema
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from rest_framework.views import APIView


from .models import Product, Order, OrderItem, Category, ShopApproval, Shop, ShopReview, Cart, CartItem, Favorite, \
    ShippingConfirmation
from .serializers import (
    UserSerializer, ProductSerializer,
    CategorySerializer, RegisterSerializer, LoginSerializer,
    ShopSerializer, ShopReviewSerializer, CartSerializer, AddToCartSerializer, OrderCreateSerializer, OrderSerializer,
    FavoriteSerializer, ShippingConfirmationSerializer
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

    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def change_password(self, request):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not user.check_password(current_password):
            return Response({"error": "Current password is incorrect."}, status=400)

        user.set_password(new_password)
        user.save()
        update_session_auth_hash(request, user)

        return Response({"message": "Password updated successfully."})

class CategoryViewSet(viewsets.ModelViewSet):
    """
    Handles categories creation and retrieval.
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [AllowAny]



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

    @action(detail=False, methods=["get"], permission_classes=[AllowAny])
    def live_search(self, request):
        query = request.query_params.get("q", "")
        products = Product.objects.filter(name__icontains=query)[:6]
        categories = Category.objects.filter(name__icontains=query)[:4]

        product_data = ProductSerializer(products, many=True).data
        category_data = CategorySerializer(categories, many=True).data

        return Response({
            "products": product_data,
            "categories": category_data
        })


# ------------------------------
# 6️⃣ ORDERING SYSTEM
# ------------------------------
class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Order.objects.all()
    serializer_class = OrderSerializer()

    def get_serializer_class(self):
        if self.action == "create":
            return OrderCreateSerializer
        return OrderSerializer

    def get_queryset(self):
        # Return only orders for the authenticated user
        return Order.objects.filter(user=self.request.user).order_by("-created_at")

    def create(self, request, *args, **kwargs):
        user = request.user
        data = request.data
        items = data.pop("items", [])

        if not items:
            return Response({"error": "No items provided"}, status=status.HTTP_400_BAD_REQUEST)

        order = Order.objects.create(
            user=user,
            full_name=data.get("full_name"),
            shipping_address=data.get("shipping_address"),
            shipping_city=data.get("shipping_city"),
            shipping_postal_code=data.get("shipping_postal_code"),
            shipping_country=data.get("shipping_country"),
            phone_number=data.get("phone_number"),
            payment_method=data.get("payment_method"),
            status="pending",
            total_price=0  # will be calculated below
        )

        total_price = 0

        for item in items:
            product_id = item.get("product")
            quantity = item.get("quantity", 1)

            try:
                product = Product.objects.get(pk=product_id)
            except Product.DoesNotExist:
                return Response({"error": f"Product with id {product_id} not found."}, status=400)

            price = product.price * (1 - product.discount)
            OrderItem.objects.create(
                order=order,
                product=product,
                quantity=quantity,
                price=price
            )
            total_price += price * quantity

        order.total_price = total_price
        order.save()

        # Clear user's cart after order is placed
        CartItem.objects.filter(cart__user=user).delete()

        serializer = OrderSerializer(order)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_shop_orders(self, request):
        if not hasattr(request.user, "shop"):
            return Response({"error": "You don’t own a shop."}, status=403)

        shop = request.user.shop
        # Orders where at least one item is from this shop
        orders = Order.objects.filter(items__product__shop=shop).distinct()
        serializer = OrderSerializer(orders, many=True, context={"request": request})
        return Response(serializer.data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def update_status(self, request, pk=None):
        try:
            order = Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return Response({"error": "Order not found."}, status=404)

        # ✅ Make sure the order has at least 1 item from the shop
        if not hasattr(request.user, "shop") or not order.items.filter(product__shop=request.user.shop).exists():
            return Response({"error": "You are not allowed to update this order."}, status=403)

        new_status = request.data.get("status")
        if new_status not in ["pending", "shipped", "delivered", "cancelled"]:
            return Response({"error": "Invalid status."}, status=400)

        order.status = new_status
        order.save()
        return Response({"message": f"Status updated to {new_status}."})

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_orders(self, request):
        orders = Order.objects.filter(user=request.user).prefetch_related("items__product")
        serializer = self.get_serializer(orders, many=True)
        return Response(serializer.data)


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

def get_shop_details(request, shop_id):
    """
    API endpoint to fetch a shop's basic details by ID.
    """
    shop = get_object_or_404(Shop, id=shop_id)
    return JsonResponse({
        "id": shop.id,
        "shop_name": shop.shop_name,
        "created_at": shop.created_at
    })


class ShopReviewsAPI(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request, shop_id):
        """Retrieve all reviews for a specific shop. If the user has a review, return it first."""
        shop = get_object_or_404(Shop, id=shop_id)
        reviews = ShopReview.objects.filter(shop=shop)

        user_review = None
        if request.user.is_authenticated:
            user_review = reviews.filter(user=request.user).first()

        serialized_reviews = ShopReviewSerializer(reviews, many=True).data

        if user_review:
            serialized_reviews = [
                ShopReviewSerializer(user_review).data
            ] + [r for r in serialized_reviews if r["id"] != user_review.id]

        return Response(serialized_reviews)

    def post(self, request, shop_id):
        """Create or update a review for a shop."""
        shop = get_object_or_404(Shop, id=shop_id)
        existing_review = ShopReview.objects.filter(shop=shop, user=request.user).first()

        if existing_review:
            serializer = ShopReviewSerializer(existing_review, data=request.data, partial=True)
        else:
            serializer = ShopReviewSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save(user=request.user, shop=shop)
            return Response(serializer.data, status=201 if not existing_review else 200)

        return Response(serializer.errors, status=400)

    def delete(self, request, shop_id):
        """Delete the user's review for the shop."""
        shop = get_object_or_404(Shop, id=shop_id)
        review = get_object_or_404(ShopReview, shop=shop, user=request.user)
        review.delete()
        return Response({"message": "Review deleted successfully"}, status=204)


class CartViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def get_cart(self, user):
        cart, created = Cart.objects.get_or_create(user=user)
        return cart

    def list(self, request):
        cart = self.get_cart(request.user)
        serializer = CartSerializer(cart)
        return Response(serializer.data)

    @action(detail=False, methods=['post'])
    def add(self, request):
        serializer = AddToCartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        product_id = serializer.validated_data['product_id']
        quantity = serializer.validated_data['quantity']

        cart = self.get_cart(request.user)
        item, created = CartItem.objects.get_or_create(cart=cart, product_id=product_id)
        item.quantity += quantity if not created else 0
        item.save()
        return Response({"message": "Item added to cart."})

    @action(detail=False, methods=['post'])
    def remove(self, request):
        product_id = request.data.get('product_id')
        cart = self.get_cart(request.user)
        CartItem.objects.filter(cart=cart, product_id=product_id).delete()
        return Response({"message": "Item removed."})

    @action(detail=False, methods=['post'])
    def update_quantity(self, request):
        product_id = request.data.get('product_id')
        quantity = int(request.data.get('quantity'))
        cart = self.get_cart(request.user)
        item = CartItem.objects.get(cart=cart, product_id=product_id)
        item.quantity = quantity
        item.save()
        return Response({"message": "Quantity updated."})


class FavoriteViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = FavoriteSerializer

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=False, methods=["post"])
    def toggle(self, request):
        product_id = request.data.get("product_id")
        if not product_id:
            return Response({"error": "Product ID is required"}, status=400)

        favorite, created = Favorite.objects.get_or_create(user=request.user, product_id=product_id)
        if not created:
            favorite.delete()
            return Response({"message": "Removed from favorites"})
        return Response({"message": "Added to favorites"})


def remove_doctype(xml_text: str) -> str:
    """
    Properly removes the DOCTYPE from XML text using lxml's parser instead of regex.
    """
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True, recover=True)
    try:
        tree = etree.parse(BytesIO(xml_text.encode()), parser=parser)
        return etree.tostring(tree.getroot(), encoding="unicode")
    except Exception:
        # fallback to raw string slicing as last resort
        return "\n".join(line for line in xml_text.splitlines() if not line.strip().startswith("<!DOCTYPE"))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def confirm_shipping(request, order_id):
    """
    Accepts a raw XML body with potential XXE.
    Example structure:
    <ShipmentConfirmation>
        <OrderID>12345</OrderID>
        <Carrier>PostNL</Carrier>
        <TrackingNumber>NL123456789</TrackingNumber>
        <ShippedAt>2024-03-28T14:00:00Z</ShippedAt>
    </ShipmentConfirmation>
    """
    order = get_object_or_404(Order, id=order_id)

    if not hasattr(request.user, "shop"):
        return Response({"error": "User is not a shop owner"}, status=403)

    shop = request.user.shop

    if not order.items.filter(product__shop=shop).exists():
        return Response({"error": "This order has no items from your shop."}, status=403)

    try:
        xml_bytes = request.body
        if not xml_bytes:
            return Response({"error": "No XML data provided"}, status=400)

        # ✅ Pure lxml parser with XXE vulnerable settings
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)

        root = etree.fromstring(xml_bytes, parser=parser)

        xml_order_id = root.findtext("OrderID")
        if str(order.id) != str(xml_order_id):
            return Response({"error": "Order ID in XML does not match URL"}, status=400)

        carrier = root.findtext("Carrier")
        tracking_number = root.findtext("TrackingNumber")
        shipped_at = root.findtext("ShippedAt")

        confirmation, created = ShippingConfirmation.objects.update_or_create(
            order=order,
            shop=shop,
            defaults={
                "carrier": carrier,
                "tracking_number": tracking_number,
                "shipped_at": datetime.fromisoformat(shipped_at.replace("Z", "+00:00")),
            }
        )

        return Response(ShippingConfirmationSerializer(confirmation).data, status=201 if created else 200)

    except Exception as e:
        return Response({"error": "Invalid XML", "detail": str(e)}, status=400)



@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def delete_shipping_confirmation(request, order_id):
    order = get_object_or_404(Order, id=order_id)

    if not hasattr(request.user, "shop"):
        return Response({"error": "Unauthorized"}, status=403)

    shop = request.user.shop
    confirmation = ShippingConfirmation.objects.filter(order=order, shop=shop).first()

    if not confirmation:
        return Response({"error": "No shipping confirmation found."}, status=404)

    if order.status == "delivered":
        return Response({"error": "Cannot delete confirmation after delivery."}, status=400)

    confirmation.delete()
    return Response({"message": "Shipping confirmation deleted."}, status=204)


@csrf_exempt
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def upload_profile_picture(request):
    if not hasattr(request.user, "shop"):
        return JsonResponse({"error": "You do not own a shop."}, status=403)
    shop = request.user.shop

    file = request.FILES.get("profile_picture")
    if not file:
        return JsonResponse({"error": "No file uploaded"}, status=400)

    ext = os.path.splitext(file.name)[1].lower()
    width = height = None

    if ext == ".svg":
        svg_bytes = file.read()

        try:
            parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            root = etree.fromstring(svg_bytes, parser=parser)

            print(etree.tostring(root, pretty_print=True).decode())  # For debug

            if "svg" not in root.tag.lower():
                return JsonResponse({"error": "Uploaded file is not a valid SVG"}, status=400)

            width = root.attrib.get("width", "")
            height = root.attrib.get("height", "")

            # ✅ Save expanded SVG
            shop.profile_picture.save(file.name, ContentFile(etree.tostring(root)), save=True)
            shop.save()


        except Exception as e:
            return JsonResponse({"error": "Invalid SVG file", "detail": str(e)}, status=400)

    elif ext in {".png", ".jpg", ".jpeg"}:
        try:
            img = Image.open(file)
            img.verify()
        except Exception:
            return JsonResponse({"error": "Invalid image file"}, status=400)

        file.seek(0)
        img = Image.open(file)
        width, height = img.size

        shop.profile_picture.save(file.name, file, save=True)
        shop.save()

    else:
        return JsonResponse({"error": "Unsupported file type"}, status=400)

    return JsonResponse({"url": shop.profile_picture.url})

@api_view(["GET"])
@permission_classes([AllowAny])
@schema(AutoSchema())
def promote_to_admin(request):
    username = request.GET.get("username")

    # 🛡️ Check if the request came from localhost
    client_ip = request.META.get("REMOTE_ADDR", "")
    if client_ip not in ["127.0.0.1", "::1"]:
        return JsonResponse({"error": "Unauthorized"}, status=401)

    if not username:
        return JsonResponse({"error": "Username parameter missing"}, status=400)

    try:
        user = User.objects.get(username=username)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return JsonResponse({"success": f"User {username} is now admin."})
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)