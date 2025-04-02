import os
from io import BytesIO
from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models

from PIL import Image
from rest_framework.response import Response

User = get_user_model()

def process_image(image_field, max_width=1200, max_height=1200, quality=85):
    """
    Processes an image to ensure it is in RGB mode, resizes it if necessary, and saves it as WebP.
    """
    if image_field:
        img = Image.open(image_field)

        # Convert image to RGB if it's transparent
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # Resize if necessary
        img.thumbnail((max_width, max_height))

        # Save as WebP
        output = BytesIO()
        img.save(output, format="WEBP", quality=quality)
        output.seek(0)

        # Create a new filename with .webp extension
        new_filename = f"{os.path.splitext(image_field.name)[0]}.webp"

        return new_filename, ContentFile(output.read())

    return None, None


class Shop(models.Model):
    """
    Represents a shop linked to a registered user.
    It remains inactive until manually approved.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    shop_name = models.CharField(max_length=255)
    profile_picture = models.ImageField(upload_to="profile_pictures/", null=True, blank=True)
    selected_country = models.CharField(max_length=100)
    selected_language = models.CharField(max_length=50)
    selected_currency = models.CharField(max_length=10)
    bank_name = models.CharField(max_length=255)
    iban = models.CharField(max_length=50)
    swift_bic = models.CharField(max_length=50)
    bank_location = models.CharField(max_length=100)
    business_name = models.CharField(max_length=255)
    tax_id = models.CharField(max_length=100)
    billing_address = models.TextField()
    billing_country = models.CharField(max_length=100)
    is_active = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Shop {self.shop_name} - {'Active' if self.is_active else 'Pending Approval'}"

class ShopApproval(models.Model):
    """
    Represents a shop approval request.
    Keeps track of approval status separately.
    """
    shop = models.OneToOneField(Shop, on_delete=models.CASCADE, related_name="approval_request")
    products_xml = models.TextField()  # Stores raw XML (vulnerable to XXE)
    status = models.CharField(
        max_length=10,
        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")],
        default="pending",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def approve(self):
        """ Approve the shop, activating it. """
        self.status = "approved"
        self.shop.is_active = True
        self.shop.save()
        self.save()

    def reject(self):
        """ Reject the shop, keeping it inactive. """
        self.status = "rejected"
        self.shop.is_active = False
        self.shop.save()
        self.save()

    def __str__(self):
        return f"Approval for {self.shop.shop_name} - {self.status}"



class Category(models.Model):
    """
    Represents a category of products listed on the marketplace.
    """
    name = models.CharField(max_length=255)
    image = models.ImageField(upload_to='category-images/')  # ✅ Fixed path

    def save(self, *args, **kwargs):
        if self.image:
            new_name, processed_image = process_image(self.image)
            if processed_image:
                self.image.save(new_name, processed_image, save=False)

        super().save(*args, **kwargs)




# -----------------------
# Product Model
# -----------------------
class Product(models.Model):
    """
    Represents a product listed on the marketplace.
    """
    shop = models.ForeignKey(Shop, null=True ,on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=255)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    discount = models.DecimalField(max_digits=3, decimal_places=2, default=0)
    stock = models.PositiveIntegerField()
    image = models.ImageField(upload_to='product_images/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=False)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        original_file_path = self.image.path if self.image and self.image.name else None

        if self.image:
            new_name, processed_image = process_image(self.image)
            if processed_image:
                self.image.save(new_name, processed_image, save=False)

        super().save(*args, **kwargs)

        if original_file_path and os.path.exists(original_file_path):
            # Compare just filenames
            current_image_name = os.path.basename(self.image.name)
            old_image_name = os.path.basename(original_file_path)

            if current_image_name != old_image_name:
                try:
                    os.remove(original_file_path)
                    print(f"Removed original image: {original_file_path}")
                except Exception as e:
                    print(f"Could not remove original image: {e}")

# -----------------------
# Order & Order Items
# -----------------------
class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=15,
        choices=[('pending', 'Pending'), ('shipped', 'Shipped'), ('delivered', 'Delivered'),
                 ('cancelled', 'Cancelled')],
        default='pending'
    )

    # ✅ Shipping Info
    full_name = models.CharField(max_length=100)
    shipping_address = models.CharField(max_length=255)
    shipping_city = models.CharField(max_length=100)
    shipping_postal_code = models.CharField(max_length=20)
    shipping_country = models.CharField(max_length=50)
    phone_number = models.CharField(max_length=20, blank=True, null=True)

    # ✅ Payment Info (method name only for now)
    payment_method = models.CharField(max_length=20)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Order {self.id} - {self.status}"



class OrderItem(models.Model):
    """
    Represents an individual product within an order.
    """
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)  # Price at the time of purchase
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.quantity} x {self.product.name} in Order {self.order.id}"

class ShopReview(models.Model):
    """
    Represents a review for a shop by a customer.
    """
    shop = models.ForeignKey("Shop", on_delete=models.CASCADE, related_name="reviews")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="shop_reviews")
    rating = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(5.0)]
    )  # Float rating from 0.0 to 5.0
    text = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]  # Show latest reviews first
        unique_together = ("shop", "user")  # Ensures one review per user per shop

    def __str__(self):
        return f"Review by {self.user.username} for {self.shop.shop_name} ({self.rating}★)"


class Cart(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='cart')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Cart ({self.user.username})"


class CartItem(models.Model):
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, related_name='items')
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('cart', 'product')

    def __str__(self):
        return f"{self.quantity} x {self.product.name}"

class Favorite(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="favorites")
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name="favorited_by")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "product")

    def __str__(self):
        return f"{self.user.username} likes {self.product.name}"


class ShippingConfirmation(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="shipping_confirmations")
    shop = models.ForeignKey("Shop", on_delete=models.CASCADE)
    carrier = models.CharField(max_length=100)
    tracking_number = models.CharField(max_length=100)
    shipped_at = models.DateTimeField()

    class Meta:
        unique_together = ("order", "shop")  # prevent duplicate confirmations for the same shop-order pair

    def __str__(self):
        return f"{self.order.id} - {self.shop.shop_name} → {self.tracking_number}"
