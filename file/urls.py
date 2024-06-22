

from django.urls import path
from file import views
from rest_framework.authtoken.views import obtain_auth_token
urlpatterns = [
    path('ops/login/', views.ops_user_login, name='ops_user_login'),
    path('ops/upload/', views.ops_user_upload_file, name='ops_user_upload_file'),
    path('client/signup/', views.client_user_signup, name='client_user_signup'),
    path('client/email-verify/', views.client_user_email_verify, name='client_user_email_verify'),
    path('client/login/', views.client_user_login, name='client_user_login'),
    path('client/files/', views.client_user_list_files, name='client_user_list_files'),
    path('client/download/<int:file_id>/', views.client_user_download_file, name='client_user_download_file'),
    path('client/login/', obtain_auth_token, name='client_user_obtain_token'),
]
