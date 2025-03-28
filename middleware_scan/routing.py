# your_app/routing.py
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/middleware_scan/weblogic/$', consumers.MiddlewareScanConsumer.as_asgi()),
    re_path(r'ws/middleware_scan/tomcat/$', consumers.MiddlewareScanConsumer.as_asgi()),
    re_path(r'ws/middleware_scan/thinkphp/$', consumers.ThinkPHPConsumer.as_asgi()),
    re_path(r'ws/struts2/info/$', consumers.Struts2Consumer.as_asgi()),
    re_path(r'ws/struts2/scan/$', consumers.Struts2Consumer.as_asgi()),
    re_path(r'ws/struts2/exploit/$', consumers.Struts2Consumer.as_asgi()),
    re_path(r'ws/spring/$', consumers.SpringScanConsumer.as_asgi()),
    re_path(r'ws/laravel/$', consumers.LaravelConsumer.as_asgi()),
    re_path(r'ws/phpggc/$', consumers.PHPGGCConsumer.as_asgi()),
    re_path(r'ws/ssti/$', consumers.SSTIConsumer.as_asgi()),
]