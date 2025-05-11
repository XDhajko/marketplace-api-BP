import json
import os
import shutil
import subprocess
from datetime import datetime
from PIL import Image
from io import BytesIO
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import update_last_login
from django.core.files.base import ContentFile, File
from django.core.files.storage import default_storage
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from rest_framework import viewsets, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes, schema
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly, IsAdminUser
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from rest_framework.views import APIView
from .permissions import IsShopOwnerOrReadOnly, IsOrderFromUserShop

from .models import Product, Order, OrderItem, Category, ShopApproval, Shop, ShopReview, Cart, CartItem, Favorite, \
    ShippingConfirmation
from .serializers import (
    UserSerializer, ProductSerializer,
    CategorySerializer, RegisterSerializer, LoginSerializer,
    ShopSerializer, ShopReviewSerializer, CartSerializer, AddToCartSerializer, OrderCreateSerializer, OrderSerializer,
    FavoriteSerializer, ShippingConfirmationSerializer
)
from lxml import etree

from django.conf import settings

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
    permission_classes = [IsAdminUser]

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

    permission_classes = [IsAuthenticatedOrReadOnly]

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()



class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsShopOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(shop=self.request.user.shop)

    def perform_update(self, serializer):
        product = self.get_object()
        if product.shop.user != self.request.user:
            raise PermissionDenied("You cannot edit products from other shops.")
        serializer.save()

        old_image_path = product.image.path if product.image else None
        if old_image_path and os.path.exists(old_image_path):
            updated_instance = self.get_object()
            if updated_instance.image.path != old_image_path:
                try:
                    os.remove(old_image_path)
                except Exception as e:
                    print(f"Could not delete old image: {e}")

    def perform_destroy(self, instance):
        if instance.shop.user != self.request.user:
            raise PermissionDenied("You cannot delete products from other shops.")
        instance.delete()

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticatedOrReadOnly])
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

    @action(detail=False, methods=["get"], permission_classes=[IsShopOwnerOrReadOnly])
    def my_shop(self, request):
        if not hasattr(request.user, 'shop'):
            raise PermissionDenied("You do not own a shop.")
        products = Product.objects.filter(shop=request.user.shop)
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)


class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Order.objects.all()

    def get_serializer_class(self):
        if self.action == "create":
            return OrderCreateSerializer
        return OrderSerializer

    def get_queryset(self):
        return Order.objects.filter(user=self.request.user)

    def create(self, request, *args, **kwargs):
        data = request.data
        items = data.pop("items", [])

        if not items:
            return Response({"error": "No items provided"}, status=status.HTTP_400_BAD_REQUEST)

        order = Order.objects.create(
            user=request.user,
            full_name=data.get("full_name"),
            shipping_address=data.get("shipping_address"),
            shipping_city=data.get("shipping_city"),
            shipping_postal_code=data.get("shipping_postal_code"),
            shipping_country=data.get("shipping_country"),
            phone_number=data.get("phone_number"),
            payment_method=data.get("payment_method"),
            status="pending",
            total_price=0
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
            OrderItem.objects.create(order=order, product=product, quantity=quantity, price=price)
            total_price += price * quantity

        order.total_price = total_price
        order.save()

        CartItem.objects.filter(cart__user=request.user).delete()

        serializer = OrderSerializer(order)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def my_shop_orders(self, request):
        shop = request.user.shop
        orders = Order.objects.filter(items__product__shop=shop).distinct()
        serializer = OrderSerializer(orders, many=True, context={"request": request})
        return Response(serializer.data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated, IsOrderFromUserShop])
    def update_status(self, request, pk=None):
        order = self.get_object()

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


@api_view(['POST'])
@permission_classes([IsAuthenticated])
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

def run_xml_as_seller(xml_data):
    result = subprocess.run(
        ["sudo", "-u", "xxe_seller", "python3", "/opt/xxe/sandboxed_xxe_parser.py"],
        input=xml_data.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )

    if result.returncode != 0:
        raise Exception(result.stderr.decode())

    return result.stdout.decode()


class SubmitShopApplication(APIView):
    """
    Handles the submission of shop applications.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        xml_data = request.body.decode("utf-8")

        try:
            parsed_xml = run_xml_as_seller(xml_data)
            root = etree.fromstring(parsed_xml.encode("utf-8"))
            #parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
            #root = etree.fromstring(xml_data, parser=parser)

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

            # Create the shop
            # Check if shop already exists for the user
            shop, created = Shop.objects.get_or_create(user=request.user)

            # Update fields with new data
            shop.shop_name = shop_name
            shop.selected_country = selected_country
            shop.selected_language = selected_language
            shop.selected_currency = selected_currency
            shop.bank_name = bank_name
            shop.iban = iban
            shop.swift_bic = swift_bic
            shop.bank_location = bank_location
            shop.business_name = business_name
            shop.tax_id = tax_id
            shop.billing_address = billing_address
            shop.billing_country = billing_country
            shop.is_active = False
            shop.save()

            # Process Products from XML, but only replace after all are validated
            products_xml = root.find("Products")
            new_products = []

            if products_xml is not None:
                for product in products_xml.findall("Product"):
                    try:
                        title = product.find("title").text or "Unnamed Product"
                        description = product.find("description").text or ""
                        price = product.find("price").text or "0.00"
                        quantity = product.find("quantity").text or "1"
                        image_url = product.find("image").text or ""

                        category_field = product.find("category").text or "Uncategorized"

                        # Handle category by ID if numeric, else by name
                        if category_field.isdigit():
                            category = Category.objects.filter(pk=int(category_field)).first()
                            if category is None:
                                category = Category.objects.create(name="Uncategorized")
                        else:
                            category, _ = Category.objects.get_or_create(name=category_field)

                        image_file = None

                        if image_url:
                            try:
                                local_image_path = image_url.replace("http://10.10.10.30/media/", "")
                                old_path = os.path.join(settings.MEDIA_ROOT, local_image_path)
                                image_name = os.path.basename(old_path)
                                new_path = os.path.join(settings.MEDIA_ROOT, "product_images", image_name)
                                os.makedirs(os.path.dirname(new_path), exist_ok=True)
                                shutil.move(old_path, new_path)

                                with open(new_path, "rb") as f:
                                    file_content = f.read()

                                image_file = File(BytesIO(file_content), name=image_name)

                            except Exception as e:
                                print(f"❌ Image processing failed: {e}")
                                raise e  # force this product to fail if image breaks

                        new_products.append(Product(
                            shop=shop,
                            name=title,
                            description=description,
                            price=price,
                            stock=int(quantity),
                            category=category,
                            image=image_file,
                            is_active=False,
                        ))

                    except Exception as err:
                        return JsonResponse({"error": f"Product parsing failed: {str(err)}"}, status=400)

            # ✅ If all products are parsed successfully, replace the old ones
            if new_products:
                Product.objects.filter(shop=shop).delete()
                Product.objects.bulk_create(new_products)

            ShopApproval.objects.filter(shop=shop).delete()
            ShopApproval.objects.create(shop=shop, products_xml=xml_data)

            return JsonResponse(
                {
                    "message": "Your shop was created and is waiting for approval.",
                    "shop_id": shop.id,
                    "shop_name": shop.shop_name
                }
            )

        except Exception as e:
            return JsonResponse({"error": "Invalid XML format", "details": str(e)}, status=400)

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



@method_decorator(csrf_exempt, name='dispatch')
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

class ShopDetailView(APIView):
    permission_classes = [AllowAny]
    def get(self, request, shop_id):
        shop = get_object_or_404(Shop, id=shop_id)
        return Response({
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


def parse_xml_with_docker(xml_bytes):
    proc = subprocess.run(
        ["docker", "run", "-i", "--rm", "--network=host","-v", "/var/log/auditing:/var/log/auditing","-v","/tmp/reports:/tmp/reports", "xxe-parser:php56"],
        input=xml_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5
    )
    if proc.returncode != 0:
        raise Exception("Docker parsing failed: " + proc.stderr.decode())
    return proc.stdout.decode()


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

        parsed_output = parse_xml_with_docker(xml_bytes)
        data = json.loads(parsed_output)  # The PHP script must output a JSON dict!

        xml_order_id = data.get("OrderID")
        if str(order.id) != str(xml_order_id):
            return Response({"error": "Order ID in XML does not match URL"}, status=400)

        carrier = data.get("Carrier")
        tracking_number = data.get("TrackingNumber")
        shipped_at = data.get("ShippedAt")

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

def run_xml_as_uploader(xml_data):
    result = subprocess.run(
        ["sudo", "-u", "xxe_upload", "python3", "/opt/xxe/sandboxed_xxe_parser.py"],
        input=xml_data.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )

    if result.returncode != 0:
        raise Exception(result.stderr.decode())

    return result.stdout.decode()

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
            parsed_svg = run_xml_as_uploader(svg_bytes.decode("utf-8"))
            root = etree.fromstring(parsed_svg.encode("utf-8"))

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


