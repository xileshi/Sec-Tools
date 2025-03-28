from django.urls import path
from . import views

app_name = 'middleware_scan'

urlpatterns = [
    path('', views.main, name='main'),  # 主页面路由
    path('spring/', views.spring_scan, name='spring_scan'),
    path('struts2/', views.struts2_scan, name='struts2_scan'),
    path('thinkphp/', views.thinkphp_scan, name='thinkphp'),
    path('tomcat/', views.tomcat_scan, name='tomcat'),
    path('weblogic/', views.weblogic_scan, name='weblogic_scan'),
    path('laravel/', views.laravel_scan, name='laravel_scan'),
    path('phpggc/', views.phpggc_scan, name='phpggc_scan'),
    path('ssti/', views.ssti_scan, name='ssti_scan'),
]