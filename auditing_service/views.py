from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.authtoken.models import Token
from api.models import Shop, ShopApproval, Product
from datetime import datetime
import os
import json

from rest_framework.permissions import AllowAny

User = get_user_model()

# 1. Approve a shop
@api_view(["POST"])
@permission_classes([AllowAny])
def approve_shop(request, shop_id):
    approval = get_object_or_404(ShopApproval, shop_id=shop_id)

    if approval.status != "pending":
        return JsonResponse({"error": "Shop already processed"}, status=400)

    # Mark as approved
    approval.status = "approved"
    approval.save()

    # Activate the shop
    approval.shop.is_active = True
    approval.shop.save()

    # Activate products under this shop
    Product.objects.filter(shop=approval.shop).update(is_active=True)

    return JsonResponse({"message": f"Shop '{approval.shop.shop_name}' approved."})

# 2. Reject a shop
@api_view(["POST"])
@permission_classes([AllowAny])
def reject_shop(request, shop_id):
    approval = get_object_or_404(ShopApproval, shop_id=shop_id)

    if approval.status != "pending":
        return JsonResponse({"error": "Shop already processed"}, status=400)

    # Mark as rejected
    approval.status = "rejected"
    approval.save()

    return JsonResponse({"message": f"Shop '{approval.shop.shop_name}' rejected."})


# 3. Return user token info
@api_view(["GET"])
@permission_classes([AllowAny])
def user_report(request, username):
    user = get_object_or_404(User, username=username)
    token = Token.objects.filter(user=user).first()

    return JsonResponse({
        "username": user.username,
        "email": user.email,
        "is_staff": user.is_staff,
        "is_active": user.is_active,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "token": token.key if token else None
    })


# 4. Aggregate shop statuses
@api_view(["GET"])
@permission_classes([AllowAny])
def shop_status_stats(request):
    stats = {
        "approved": ShopApproval.objects.filter(status="approved").count(),
        "pending": ShopApproval.objects.filter(status="pending").count(),
        "rejected": ShopApproval.objects.filter(status="rejected").count()
    }
    return JsonResponse(stats)


# 5. Return recent login events (mocked)
@api_view(["GET"])
@permission_classes([AllowAny])
def login_events(request):
    recent_users = User.objects.order_by("-last_login")[:5]
    logins = [
        {
            "username": u.username,
            "last_login": u.last_login.isoformat() if u.last_login else "Never"
        }
        for u in recent_users
    ]
    return JsonResponse({"logins": logins})


# 6. Shop report with approval + products
@api_view(["GET"])
@permission_classes([AllowAny])
def shop_report(request, shop_id):
    shop = get_object_or_404(Shop, id=shop_id)
    approval = ShopApproval.objects.filter(shop=shop).first()
    products = list(Product.objects.filter(shop=shop).values("name", "is_active"))

    return JsonResponse({
        "shop_name": shop.shop_name,
        "status": approval.status if approval else "unknown",
        "products": products
    })


# 7. User activity report (writes to file)
@api_view(["GET"])
@permission_classes([AllowAny])
def generate_user_report(request, username):
    user = get_object_or_404(User, username=username)
    token = Token.objects.filter(user=user).first()

    report = {
        "username": user.username,
        "email": user.email,
        "last_login": user.last_login.isoformat() if user.last_login else "Never",
        "is_staff": user.is_staff,
        "has_token": bool(token),
        "token": token.key if token else None,
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "timestamp": datetime.utcnow().isoformat()
    }

    os.makedirs("/tmp/reports", exist_ok=True)
    with open(f"/tmp/reports/{username}_report.json", "w") as f:
        json.dump(report, f, indent=2)

    return JsonResponse(report)
