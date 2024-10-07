
from django.urls import path
from . import views


urlpatterns = [
    path('login/', views.login, name='login'),
    path('signup/', views.register, name='signup'),
    path('roles/register/', views.register_role, name='register_role'),
    path('get-csrf-token/', views.get_csrf_token, name='get_csrf_token'),
]
