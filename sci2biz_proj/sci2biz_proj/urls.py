from django.urls import path, include


urlpatterns = [
    path('api/auth/', include('sci2biz_app.urls')),
    path('api/token/', include('sci2biz_app.token')),
    path('api/', include('sci2biz_app.refresh_password')),
    path('api/', include('sci2biz_app.swagger')),
    path('api/docs/', include('sci2biz_app.swagger')),
]
