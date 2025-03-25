import subprocess
import sys

from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

def main(request):
    return render(request, 'middleware_scan/main.html')

@csrf_exempt
def django_scan(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target')
        result = run_django_scan(target)
    return render(request, 'middleware_scan/django.html', {'result': result})

@csrf_exempt
def spring_scan(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target')
        result = run_spring_scan(target)
    return render(request, 'middleware_scan/spring.html', {'result': result})

@csrf_exempt
def express_scan(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target')
        result = run_express_scan(target)
    return render(request, 'middleware_scan/express.html', {'result': result})

def run_django_scan(target):
    # 这里编写Django扫描逻辑
    return f"Django扫描结果 for {target}"

def run_spring_scan(target):
    # 这里编写Spring扫描逻辑
    return f"Spring扫描结果 for {target}"

def run_express_scan(target):
    # 这里编写Express扫描逻辑
    return f"Express扫描结果 for {target}"

@csrf_exempt
def tomcat_scan(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target')
        result = run_tomcat_scan(target)
    return render(request, 'middleware_scan/tomcat.html', {'result': result})

def run_tomcat_scan(target):
    try:
        # 调用TomcatScanPro工具并捕获输出
        process = subprocess.Popen(
            ['python', 'tools/TomcatScanPro/TomcatScanPro.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            return f"Error: {stderr}"
        return stdout
    except Exception as e:
        return str(e)

@csrf_exempt
def weblogic_scan(request):
    result = None
    if request.method == 'POST':
        target = request.POST.get('target')
        result = run_weblogic_scan(target)
    return render(request, 'middleware_scan/weblogic.html', {'result': result})

def run_weblogic_scan(target):
    # 调用 WebLogic 扫描脚本并捕获输出
    process = subprocess.Popen([sys.executable, 'tools/weblogicScanner/ws.py', '-t', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        return f"Error: {stderr.decode('utf-8')}"
    return stdout.decode('utf-8')