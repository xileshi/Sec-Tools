import subprocess
import sys
from channels.generic.websocket import WebsocketConsumer
import threading


class MiddlewareScanConsumer(WebsocketConsumer):
    def connect(self):
        self.accept()

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        target = text_data
        thread = threading.Thread(target=self.run_weblogic_scan, args=(target,))
        thread.start()

    def run_weblogic_scan(self, target):
        process = subprocess.Popen([sys.executable, 'tools/weblogicScanner/ws.py', '-t', target],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 读取和发送标准输出
        for line in iter(process.stdout.readline, b''):
            self.send(text_data=line.decode('utf-8'))

        process.stdout.close()

        # 等待进程结束并获取返回码
        return_code = process.wait()

        # 读取和发送标准错误
        if return_code != 0:
            for line in iter(process.stderr.readline, b''):
                self.send(text_data=f"Error: {line.decode('utf-8')}")

        process.stderr.close()

        # 发送进程结束的状态
        self.send(text_data=f"Process finished with return code {return_code}")