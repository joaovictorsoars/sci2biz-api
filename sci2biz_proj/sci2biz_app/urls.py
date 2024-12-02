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
    path('logged-in/', views.get_user_logged_in, name='logged-in'),
    path('refresh-token/', views.refresh_token, name='refresh-token'),
    path('demandas/create/', views.create_demanda, name='create_demanda'),
    path('demandas/', views.list_demandas, name='list_demandas'),
    path('demandas/update/response/<int:demanda_id>/', views.get_demanda_response, name='response_demanda'),
    path('demandas/delete/<int:demanda_id>/', views.delete_demanda, name='delete_demanda'),
    path('turmas/create/', views.create_turma, name='create_turma'),
    path('turmas/add/monitor/', views.add_monitor, name='add_monitor'),
    path('turmas/add/student/', views.add_student, name='add_student'),
    path('turmas/add/students/import', views.import_students, name='import_students'),
]
