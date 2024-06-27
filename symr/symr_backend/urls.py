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
    path('get_csrf_token/', views.get_csrf_token, name='get_csrf_token'),
    path('test_cookie/', views.test_cookie, name='test_cookie'),
    
]