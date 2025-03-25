from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/middleware_scan/$', consumers.MiddlewareScanConsumer.as_asgi()),
]