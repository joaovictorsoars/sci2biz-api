
from django.urls import path, re_path
from . import views
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="sci2biz API",
        default_version="v1",
        description="API para o projeto sci2biz",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contato@exemplo.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('login/', views.login, name='login'),
    path('signup/', views.register, name='signup'),
    path('list_users/', views.list_users, name='list_users'),
    path('remove_user/', views.remove_user, name='remove_user'),
    path('update_user/', views.update_user, name='update_user'),
    path('toggle_user_active_status/', views.toggle_user_active_status, name='toggle_user_active_status'),
    path('roles/register/', views.register_role, name='register_role'),
    path('get-csrf-token/', views.get_csrf_token, name='get_csrf_token'),
    path('logged-in/', views.get_user_logged_in, name='logged-in'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
]
