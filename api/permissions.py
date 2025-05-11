from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsShopOwnerOrReadOnly(BasePermission):
    """
    Allows full access only to shop owners.
    Others have read-only access.
    """
    def has_permission(self, request, view):
        # Allow safe (GET, HEAD, OPTIONS) requests for anyone
        if request.method in SAFE_METHODS:
            return True
        # Write permissions are only allowed to shop owners
        return hasattr(request.user, 'shop')

    def has_object_permission(self, request, view, obj):
        if request.method in SAFE_METHODS:
            return True
        return hasattr(request.user, 'shop') and obj.shop.user == request.user

class IsOrderFromUserShop(BasePermission):
    """
    Ensures that the order contains products belonging to the user's shop.
    """

    def has_object_permission(self, request, view, obj):
        if not hasattr(request.user, 'shop'):
            return False
        return obj.items.filter(product__shop=request.user.shop).exists()

