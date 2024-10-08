
from django.urls import path
from . import views


urlpatterns = [
    path('login/', views.login, name='login'),
    path('signup/', views.register, name='signup'),
    path('list_users/', views.list_users, name='list_users'),
    path('remove_user/', views.remove_user, name='remove_user'),
    path('update_user/', views.update_user, name='update_user'),
    path('toggle_user_active_status/', views.toggle_user_active_status, name='toggle_user_active_status'),
    path('roles/register/', views.register_role, name='register_role'),
    path('get-csrf-token/', views.get_csrf_token, name='get_csrf_token'),
    path('logged-in/', views.get_user_logged_in, name='logged-in')
]
