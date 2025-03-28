"""Sec_Tools URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from aiohttp.web_routedef import static
from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve

from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator
import middleware_scan.routing

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('webscan.urls')),    # 信息收集，前端页面
    path('', include('login.urls')),      # 登录注册
    path('', include('dirscan.urls')),    # 目录识别
    path('', include('vulnscan.urls')),   # 漏洞检测
    path('middleware_scan/', include('middleware_scan.urls')),
    path('webscan_backend/', include('webscan_backend.urls')),   # 后端接口
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
]

# WebSocket URL patterns
websocket_urlpatterns = middleware_scan.routing.websocket_urlpatterns

# 在开发环境中添加静态文件服务
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

