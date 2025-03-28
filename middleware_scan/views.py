import subprocess
import sys
import os
import traceback

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
    return render(request, 'middleware_scan/spring.html')

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
        # 获取工具目录路径
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        tool_dir = os.path.join(current_dir, 'tools', 'TomcatScanPro')
        script_path = os.path.join(tool_dir, 'TomcatScanPro.py')
        
        # 确保data目录存在
        data_dir = os.path.join(tool_dir, 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        # 准备URL文件 - 写入data目录下的urls.txt
        urls_path = os.path.join(data_dir, 'urls.txt')
        
        # 如果URL不以http开头，添加http://
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # 写入URL到文件
        with open(urls_path, 'w', encoding='utf-8') as f:
            f.write(target + '\n')
        
        # 设置环境变量
        env = os.environ.copy()
        env['PYTHONPATH'] = tool_dir + os.pathsep + env.get('PYTHONPATH', '')
        env['PYTHONIOENCODING'] = 'utf-8'  # 设置Python的IO编码
        
        # 构建命令
        cmd = [
            sys.executable,
            '-u',  # 使用无缓冲的输出
            script_path
        ]
        
        # 执行扫描
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,  # 改为False，手动处理编码
            cwd=tool_dir,
            env=env,
            bufsize=0,  # 无缓冲
        )
        
        # 读取输出并正确解码
        stdout_bytes, stderr_bytes = process.communicate()
        
        try:
            stdout = stdout_bytes.decode('gbk')  # 首先尝试GBK解码
        except UnicodeDecodeError:
            try:
                stdout = stdout_bytes.decode('utf-8')  # 如果GBK失败，尝试UTF-8
            except UnicodeDecodeError:
                stdout = stdout_bytes.decode('gb18030', errors='replace')  # 最后尝试GB18030
        
        try:
            stderr = stderr_bytes.decode('gbk')
        except UnicodeDecodeError:
            try:
                stderr = stderr_bytes.decode('utf-8')
            except UnicodeDecodeError:
                stderr = stderr_bytes.decode('gb18030', errors='replace')
        
        # 检查是否有错误
        if process.returncode != 0:
            if "ModuleNotFoundError: No module named 'yaml'" in stderr:
                try:
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyyaml'])
                    # 重新运行扫描，使用相同的编码处理
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=False,
                        cwd=tool_dir,
                        env=env,
                        bufsize=0
                    )
                    stdout_bytes, stderr_bytes = process.communicate()
                    stdout = stdout_bytes.decode('gbk', errors='replace')
                    stderr = stderr_bytes.decode('gbk', errors='replace')
                except Exception as e:
                    return f"Error: 无法安装所需依赖: {str(e)}"
            else:
                return f"Error: {stderr}"
        
        result = []
        # 添加基本信息
        result.append("=== Tomcat漏洞扫描报告 ===")
        result.append(f"目标URL: {target}")
        result.append("=" * 50)
        result.append("")
        
        # 直接显示命令行输出，保持颜色代码
        if stdout:
            # 将stdout中的转义序列替换为HTML样式
            colored_output = stdout.replace('[32m', '<span style="color: green">')\
                                 .replace('[31m', '<span style="color: red">')\
                                 .replace('[34m', '<span style="color: blue">')\
                                 .replace('[33m', '<span style="color: yellow">')\
                                 .replace('[37m', '<span style="color: white">')\
                                 .replace('[0m', '</span>')
            result.append(colored_output)
        
        if stderr and stderr.strip():  # 只在stderr不为空时添加
            result.append("\n=== 错误信息 ===")
            result.append(stderr)
        
        return "\n".join(result)
        
    except Exception as e:
        return f"Error: 执行扫描时发生错误: {str(e)}\n" + traceback.format_exc()

@csrf_exempt
def weblogic_scan(request):
    return render(request, 'weblogic.html')

def run_weblogic_scan(target):
    # 调用 WebLogic 扫描脚本并捕获输出
    process = subprocess.Popen([sys.executable, 'tools/weblogicScanner/ws.py', '-t', target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        return f"Error: {stderr.decode('utf-8')}"
    return stdout.decode('utf-8')

@csrf_exempt
def thinkphp_scan(request):
    return render(request, 'middleware_scan/thinkphp.html')

def run_thinkphp_scan(target):
    try:
        # 获取工具目录路径
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        jar_path = os.path.join(current_dir, 'tools', 'ThinkPHP.jar')
        
        # 如果URL不以http开头，添加http://
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # 构建命令
        cmd = [
            'java',
            '-jar',
            jar_path,
            '-u',  # 假设工具使用-u参数指定URL，根据实际情况修改
            target
        ]
        
        # 执行扫描
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env={'JAVA_HOME': os.environ.get('JAVA_HOME', '')},
            bufsize=0
        )
        
        # 读取输出并正确解码
        stdout_bytes, stderr_bytes = process.communicate()
        
        try:
            stdout = stdout_bytes.decode('gbk')
        except UnicodeDecodeError:
            try:
                stdout = stdout_bytes.decode('utf-8')
            except UnicodeDecodeError:
                stdout = stdout_bytes.decode('gb18030', errors='replace')
        
        try:
            stderr = stderr_bytes.decode('gbk')
        except UnicodeDecodeError:
            try:
                stderr = stderr_bytes.decode('utf-8')
            except UnicodeDecodeError:
                stderr = stderr_bytes.decode('gb18030', errors='replace')
        
        result = []
        # 添加基本信息
        result.append("=== ThinkPHP漏洞扫描报告 ===")
        result.append(f"目标URL: {target}")
        result.append("=" * 50)
        result.append("")
        
        # 添加扫描输出
        if stdout:
            result.append(stdout)
        
        if stderr and stderr.strip():
            result.append("\n=== 错误信息 ===")
            result.append(stderr)
        
        return "\n".join(result)
        
    except Exception as e:
        return f"Error: 执行扫描时发生错误: {str(e)}\n" + traceback.format_exc()

@csrf_exempt
def struts2_scan(request):
    return render(request, 'middleware_scan/struts2.html')

def laravel_scan(request):
    return render(request, 'middleware_scan/laravel.html')

@csrf_exempt
def phpggc_scan(request):
    return render(request, 'middleware_scan/phpggc.html')

@csrf_exempt
def ssti_scan(request):
    return render(request, 'middleware_scan/ssti.html')