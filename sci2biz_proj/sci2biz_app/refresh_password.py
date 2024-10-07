from django.urls import path
from . import views

urlpatterns = [
    path('refresh_password/', views.change_password, name='refresh_password'),
    path('password_reset/', views.request_password_reset, name='password_reset'),
    path('password_reset_confirm/<uidb64>/<token>/', views.confirm_password_reset, name='password_reset_confirm'),

]