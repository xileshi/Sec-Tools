from django.urls import path
from . import views

app_name = 'middleware_scan'

urlpatterns = [
    path('', views.main, name='main'),
    path('django/', views.django_scan, name='django'),
    path('spring/', views.spring_scan, name='spring'),
    path('express/', views.express_scan, name='express'),
    path('tomcat/', views.tomcat_scan, name='tomcat'),  # 添加新的URL路由
    path('weblogic/', views.weblogic_scan, name='weblogic'),
]