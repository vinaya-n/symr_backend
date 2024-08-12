from django.urls import path
from . import views

urlpatterns = [
    # path('', views.index, name='index'),
    path('api/PMT/', views.calculatePMT, name='calculatePMT'),
    path('api/results/', views.commonResults, name='results'),
    path('api/next-months/', views.get_next_months, name='get_next_months'),
    path('api/DM/', views.payOffDebtRecos, name='payOffDebtRecos'),
    path('api/AS/', views.allocateSavings, name='allocateSavings'),
    path('api/SFG/', views.saveForGoal, name='saveForGoal'),
    path('api/INV/', views.investRecos, name='investRecos'),
    path('api/upload/', views.upload_file, name='upload_file'),
    path('api/list_files/', views.list_user_files, name='list_files'),
    path('api/files/view/', views.view_decrypted_file, name='view_decrypted_file'),
    path('api/files/delete/', views.delete_file, name='delete_file'),
    path('get_csrf_token/', views.get_csrf_token, name='get_csrf_token'),
    path('test_cookie/', views.test_cookie, name='test_cookie'),
    path('api/google_drive_auth/', views.google_drive_auth, name='google_drive_auth'),
    path('api/upload_to_google_drive/', views.upload_to_google_drive, name='upload_to_google_drive'),
    path('api/list_google_drive_files/', views.list_google_drive_files, name='list_google_drive_files'),
    path('api/oauth2callback/', views.oauth2callback, name='oauth2callback'),
    path('api/download-users/', views.download_cognito_users, name='download-users'),
    path('api/save_to_dynamo/', views.save_to_dynamo, name='save_to_dynamo'),
    path('api/fetch_data/', views.fetch_data, name='fetch_data'),
    #path('api/print-env/', views.print_env_vars, name='print_env_vars'),
    #path('api/oauth2callback/api/upload_to_google_drive', views.upload_to_google_drive, name='upload_to_google_drive'),
    
]