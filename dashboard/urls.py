from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    # URL untuk halaman utama yang menampilkan template
    path('', views.index, name='index'),
    
    # URL BARU untuk API data kita
    path('api/dashboard-data/', views.dashboard_data_api, name='dashboard_api_data'),
]