from django.contrib.sessions.models import Session
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from drf_spectacular.utils import extend_schema
from api.models import Shop, ShopApproval, Product
from django.utils.timezone import now
from datetime import datetime
import os
import json

User = get_user_model()


import os
from datetime import datetime
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import extend_schema
from api.models import Shop, ShopApproval, Product


# Define a general audit log directory
AUDIT_LOG_DIR = "/var/log/auditing" if os.name != "nt" else "C:/auditing_logs"
os.makedirs(AUDIT_LOG_DIR, exist_ok=True)

def log_shop_action(shop_name, status, performed_by):
    timestamp = datetime.utcnow().isoformat()
    log_entry = f"[{timestamp}] Shop '{shop_name}' was {status} by {performed_by}\n"
    with open(os.path.join(AUDIT_LOG_DIR, "shop_audit_log.txt"), "a", encoding="utf-8") as log_file:
        log_file.write(log_entry)


@extend_schema(
    description=f"""
Approve a pending shop.

This endpoint activates the shop and all its products **only if its status is currently 'pending'**.

All actions are logged for auditing purposes. Each approval is recorded to /var/log/auditing/shop_audit_log.txt.

Each log entry contains:
- Shop name
- Action performed ('approved')
- UTC timestamp
- Username of the staff/admin who performed the action
""",
    responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def approve_shop(request, shop_id):
    approval = get_object_or_404(ShopApproval, shop_id=shop_id)

    if approval.status != "pending":
        return JsonResponse({"error": "Shop already processed"}, status=400)

    approval.status = "approved"
    approval.save()

    approval.shop.is_active = True
    approval.shop.save()

    Product.objects.filter(shop=approval.shop).update(is_active=True)

    performed_by = getattr(request.user, "username", "Unknown")
    log_shop_action(approval.shop.shop_name, "approved", performed_by)

    return JsonResponse({"message": f"Shop '{approval.shop.shop_name}' approved."})


@extend_schema(
    description=f"""
Reject a pending shop.

This sets the shop's approval status to 'rejected' **if it is currently 'pending'**.

All actions are logged for auditing purposes. Each rejection is recorded to /var/log/auditing/shop_audit_log.txt.

Each log entry contains:
- Shop name
- Action performed ('rejected')
- UTC timestamp
- Username of the staff/admin who performed the action
""",
    responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}}
)
@api_view(["POST"])
@permission_classes([AllowAny])
def reject_shop(request, shop_id):
    approval = get_object_or_404(ShopApproval, shop_id=shop_id)

    if approval.status != "pending":
        return JsonResponse({"error": "Shop already processed"}, status=400)

    approval.status = "rejected"
    approval.save()

    performed_by = getattr(request.user, "username", "Unknown")
    log_shop_action(approval.shop.shop_name, "rejected", performed_by)

    return JsonResponse({"message": f"Shop '{approval.shop.shop_name}' rejected."})

@extend_schema(
    description="Returns a count of shops grouped by their approval status (approved, pending, rejected).",
    responses={200: {
        "type": "object",
        "properties": {
            "approved": {"type": "integer"},
            "pending": {"type": "integer"},
            "rejected": {"type": "integer"}
        }
    }}
)
@api_view(["GET"])
@permission_classes([AllowAny])
def shop_status_stats(request):
    stats = {
        "approved": ShopApproval.objects.filter(status="approved").count(),
        "pending": ShopApproval.objects.filter(status="pending").count(),
        "rejected": ShopApproval.objects.filter(status="rejected").count()
    }
    return JsonResponse(stats)


@extend_schema(
    description="Returns the most recent 5 user login events ordered by last login date.",
    responses={200: {
        "type": "object",
        "properties": {
            "logins": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "last_login": {"type": "string"}
                    }
                }
            }
        }
    }}
)
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


@extend_schema(
    description="Generate a report for a specific shop, including its approval status and the list of its products.",
    responses={200: {
        "type": "object",
        "properties": {
            "shop_name": {"type": "string"},
            "status": {"type": "string"},
            "products": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "is_active": {"type": "boolean"}
                    }
                }
            }
        }
    }}
)
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


@extend_schema(
    description="""
Generates a full user activity and authentication report, including their token, cookies, user-agent, and more.

The data is written to a file in `/tmp/reports/{username}_full_auth.json` for offline auditing.

⚠️ WARNING: This endpoint includes sensitive user information and writes files to disk. Intended for internal use only.
""",
    responses={200: {
        "type": "object",
        "properties": {
            "username": {"type": "string"},
            "email": {"type": "string"},
            "last_login": {"type": "string"},
            "is_staff": {"type": "boolean"},
            "has_token": {"type": "boolean"},
            "token": {"type": "string"},
            "cookies": {
                "type": "object",
                "properties": {
                    "csrftoken": {"type": "string"},
                    "sessionid": {"type": "string"},
                }
            },
            "user_agent": {"type": "string"},
            "timestamp": {"type": "string"},
        }
    }}
)
@api_view(["GET"])
@permission_classes([AllowAny])
def generate_auth_report(request, username):
    user = get_object_or_404(User, username=username)
    token = Token.objects.filter(user=user).first()

    # Look for active session for the user
    session_key = None
    for session in Session.objects.filter(expire_date__gt=now()):
        data = session.get_decoded()
        if data.get('_auth_user_id') == str(user.id):  # session values are strings
            session_key = session.session_key
            break

    cookies = {
        "csrftoken": None,  # CSRF is not stored unless part of session payload
        "sessionid": session_key
    }

    report = {
        "username": user.username,
        "email": user.email,
        "last_login": user.last_login.isoformat() if user.last_login else "Never",
        "is_staff": user.is_staff,
        "has_token": bool(token),
        "token": token.key if token else None,
        "cookies": cookies,
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
        "timestamp": datetime.utcnow().isoformat()
    }

    os.makedirs("/tmp/reports", exist_ok=True)
    with open(f"/tmp/reports/{username}_full_auth.json", "w") as f:
        json.dump(report, f, indent=2)

    return JsonResponse(report)
