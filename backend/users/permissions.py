from rest_framework.permissions import BasePermission

return_message = 'You have no access.'

class IsSuperAdmin(BasePermission):
    message = return_message
    def has_permission(self, request, view):
        return bool(request.user.role.role_name == 'Admin')

class IsVendor(BasePermission):
    message = return_message
    def has_permission(self, request, view):
        return bool(request.user.role.role_name == 'Vendor')

class IsCustomer(BasePermission):
    message = return_message
    def has_permission(self, request, view):
        return bool(request.user.role.role_name == 'Customer')
    
class IsVendorOrSuperAdmin(BasePermission):
    message = return_message
    def has_permission(self, request, view):
        return bool(request.user.role.role_name == 'Vendor') or bool(request.user.role.role_name == 'Admin')