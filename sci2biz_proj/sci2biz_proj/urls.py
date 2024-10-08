from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('sci2biz_app.urls')),
    path('api/token/', include('sci2biz_app.token')),
    path('api/', include('sci2biz_app.refresh_password')),
]
