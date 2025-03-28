"""
ASGI config for Sec_Tools project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/howto/deployment/asgi/
"""

import os
import sys
import logging
import signal
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from middleware_scan import routing

# 设置 Django 环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Sec_Tools.settings')

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

try:
    # 初始化Django ASGI应用
    django_asgi_app = get_asgi_application()
    logger.info("Django ASGI application initialized successfully")

    # 创建WebSocket路由器
    websocket_router = URLRouter(routing.websocket_urlpatterns)
    logger.info("WebSocket router created successfully")
    logger.info(f"WebSocket URL patterns: {routing.websocket_urlpatterns}")

    # 创建认证中间件
    auth_middleware = AuthMiddlewareStack(websocket_router)
    logger.info("Auth middleware created successfully")

    # 配置ASGI应用
    application = ProtocolTypeRouter({
        "http": django_asgi_app,
        "websocket": auth_middleware,
    })
    logger.info("ASGI application configured successfully")

except Exception as e:
    logger.error(f"Error during ASGI configuration: {str(e)}")
    logger.error("Traceback:", exc_info=True)
    raise

def signal_handler(signum, frame):
    """处理SIGINT信号"""
    print("\n正在关闭服务器...")
    sys.exit(0)

# 注册信号处理器
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)