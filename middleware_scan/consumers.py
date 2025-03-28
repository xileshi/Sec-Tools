import subprocess
import sys
import logging
import os
import traceback
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
import threading
import json
from datetime import datetime
import re
import base64
import signal
import atexit
from django.conf import settings
import html  # 添加这行导入


logger = logging.getLogger(__name__)

class MiddlewareScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            logger.info("尝试建立WebSocket连接")
            # 只记录必要的连接信息
            logger.info(f"Client IP: {self.scope.get('client', 'unknown')}")
            await self.accept()
            logger.info("WebSocket连接已接受")
            await self.send(text_data="连接成功")
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def disconnect(self, close_code):
        logger.info(f"WebSocket disconnected with code: {close_code}")
        # 移除不必要的日志记录
        try:
            await self.send(text_data=f"连接已关闭，代码: {close_code}\n")
        except:
            pass

    async def receive(self, text_data):
        try:
            logger.info(f"收到数据: {text_data}")
            target = text_data.strip()
            if not target:
                await self.send(text_data="错误：目标地址不能为空\n")
                return
                
            await self.send(text_data=f"收到目标地址: {target}\n")
            
            # 根据路径判断是哪个扫描
            path = self.scope.get('path', '')
            if '/weblogic/' in path:
                # 使用异步方式运行 WebLogic 扫描
                await self.run_weblogic_scan(target)
            elif '/tomcat/' in path:
                # 使用异步方式运行 Tomcat 扫描
                await self.run_tomcat_scan(target)
            else:
                await self.send(text_data="错误：未知的扫描类型\n")
        except Exception as e:
            error_msg = f"接收数据时发生错误: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            await self.send(text_data=error_msg + '\n')

    async def run_weblogic_scan(self, target):
        try:
            logger.info(f"开始WebLogic扫描，目标: {target}")
            await self.send(text_data=f"开始扫描目标: {target}\n")
            
            # 获取绝对路径
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_path = os.path.join(current_dir, 'tools', 'weblogicScanner', 'ws.py')
            
            # 检查脚本是否存在
            if not os.path.exists(script_path):
                error_msg = f"错误：扫描脚本不存在: {script_path}"
                logger.error(error_msg)
                await self.send(text_data=error_msg + '\n')
                return
                
            logger.info(f"使用脚本路径: {script_path}")
            
            # 修改命令构建 - 移除-v参数，让工具扫描所有漏洞
            cmd = [
                sys.executable,
                script_path,
                '-t', 
                target
            ]
            
            # 记录完整命令
            logger.info(f"执行命令: {' '.join(cmd)}")
            await self.send(text_data=f"正在执行扫描...\n")
            
            try:
                # 在Windows上使用subprocess.Popen替代asyncio.create_subprocess_exec
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=os.path.dirname(script_path),
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # 创建异步任务来读取输出
                async def read_output():
                    while True:
                        line = process.stdout.readline()
                        if not line:
                            break
                        try:
                            if line.strip():
                                logger.debug(f"扫描输出: {line.strip()}")
                                await self.send(text_data=line)
                        except Exception as e:
                            logger.error(f"处理输出时出错: {str(e)}")
                
                # 创建异步任务来读取错误输出
                async def read_error():
                    while True:
                        line = process.stderr.readline()
                        if not line:
                            break
                        try:
                            if line.strip():
                                logger.error(f"错误输出: {line.strip()}")
                                await self.send(text_data=f"错误: {line}")
                        except Exception as e:
                            logger.error(f"处理错误输出时出错: {str(e)}")
                
                # 并行执行读取任务
                await asyncio.gather(
                    asyncio.create_task(read_output()),
                    asyncio.create_task(read_error())
                )
                
                # 等待进程结束
                return_code = process.wait()
                
                if return_code != 0:
                    await self.send(text_data=f"扫描进程异常退出，返回码: {return_code}\n")
                else:
                    await self.send(text_data="扫描完成\n")
                    
            except Exception as e:
                error_msg = f"执行扫描进程时出错: {str(e)}"
                logger.error(error_msg)
                await self.send(text_data=error_msg + '\n')
                
        except Exception as e:
            error_msg = f"扫描过程中发生错误: {str(e)}\n"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            await self.send(text_data=error_msg)
            await self.send(text_data="错误详情：" + traceback.format_exc() + '\n')

    async def run_tomcat_scan(self, target):
        try:
            logger.info(f"Starting Tomcat scan for target: {target}")
            await self.send(text_data=f"开始扫描目标: {target}\n")
            
            # 获取项目根目录和 Python 解释器路径
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            python_path = r"D:\PyCharm 2024.3.1.1\Sec-Tools\Scripts\python.exe"
            pip_path = os.path.join(os.path.dirname(python_path), 'pip.exe')
            script_path = os.path.join(project_root, 'tools', 'TomcatScanPro', 'TomcatScanPro.py')
            
            if not os.path.exists(script_path):
                error_msg = f"错误：扫描脚本不存在: {script_path}"
                logger.error(error_msg)
                await self.send(text_data=error_msg + '\n')
                return
                
            if not os.path.exists(python_path):
                error_msg = f"错误：Python解释器不存在: {python_path}"
                logger.error(error_msg)
                await self.send(text_data=error_msg + '\n')
                return
                
            logger.info(f"Using script path: {script_path}")
            logger.info(f"Using Python path: {python_path}")
            
            # 安装依赖
            requirements_path = os.path.join(project_root, 'tools', 'TomcatScanPro', 'requirements.txt')
            if os.path.exists(requirements_path):
                install_cmd = f'"{pip_path}" install -r "{requirements_path}"'
                logger.info(f"Installing dependencies: {install_cmd}")
                install_process = await asyncio.create_subprocess_shell(
                    install_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    text=True,
                    shell=True
                )
                await install_process.wait()
                if install_process.returncode != 0:
                    error_msg = "安装依赖失败"
                    logger.error(error_msg)
                    await self.send(text_data=error_msg + '\n')
                    return
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = project_root
            env['PATH'] = os.path.dirname(python_path) + os.pathsep + env.get('PATH', '')
            
            # 构建完整的命令
            cmd = f'"{python_path}" "{script_path}" -t "{target}"'
            logger.info(f"Running command: {cmd}")
            
            # 使用 subprocess 运行脚本
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=env,
                cwd=project_root,
                shell=True
            )

            # 读取和发送标准输出
            while True:
                line = await process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    logger.debug(f"Output: {line.strip()}")
                    await self.send(text_data=line)

            # 等待进程结束并获取返回码
            return_code = await process.wait()
            logger.info(f"Process finished with return code: {return_code}")

            # 读取和发送标准错误
            if return_code != 0:
                while True:
                    line = await process.stderr.readline()
                    if not line:
                        break
                    error_msg = f"Error: {line.strip()}"
                    logger.error(error_msg)
                    await self.send(text_data=error_msg + '\n')

            # 发送进程结束的状态
            await self.send(text_data=f"扫描完成，返回码: {return_code}\n")
            
        except Exception as e:
            error_msg = f"扫描过程中发生错误: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            await self.send(text_data=error_msg + '\n')

class ThinkPHPConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            await self.accept()
            await self.send(text_data="WebSocket连接成功\n")
            
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.tpscan_dir = os.path.join(current_dir, 'tools', 'TPscan')
            
            if not os.path.exists(os.path.join(self.tpscan_dir, 'TPscan.py')):
                await self.send(text_data="错误: 未找到TPscan.py文件\n")
                return
                
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            await self.send(text_data=f"连接错误: {str(e)}\n")
            await self.close()

    async def format_scan_result(self, result_str):
        try:
            # 预处理JSON字符串，清理所有换行符
            cleaned_json = result_str.replace('\\n', ' ').replace('\n', ' ')
            result = json.loads(cleaned_json)
            
            # 递归清理所有字符串值中的换行符和多余空白
            def clean_value(value):
                if isinstance(value, str):
                    return ' '.join(value.split())
                elif isinstance(value, dict):
                    return {k: clean_value(v) for k, v in value.items()}
                elif isinstance(value, list):
                    return [clean_value(item) for item in value]
                return value
            
            # 清理所有字段
            result = clean_value(result)
            
            # 格式化输出
            output = []
            output.append("[+] 漏洞扫描结果")
            output.append(f"[*] 漏洞名称: {result['vulnname']}")
            
            # 漏洞状态
            vuln_status = "存在" if result['isvul'] else "不存在"
            status_color = "red" if result['isvul'] else "green"
            output.append(f'[*] 漏洞状态: <span style="color: {status_color}">{vuln_status}</span>')
            output.append(f"[*] 目标URL: {result['vulnurl']}")
            
            # Payload信息
            if result['payload']:
                output.append("[+] Payload详情:")
                for key, value in result['payload'].items():
                    output.append(f"    {key}: {value}")
            
            # 漏洞证明
            if result['proof']:
                output.append(f"[+] 漏洞证明: {result['proof']}")
            
            # 响应信息处理
            if result['response']:
                # 提取关键信息
                if 'string(32)' in result['response']:
                    match = re.search(r'string\(32\) "(.*?)"', result['response'])
                    if match:
                        output.append(f"[+] 验证响应: {match.group(1)}")
                
                # 提取ThinkPHP版本
                version_match = re.search(r'ThinkPHP\s+V([\d.]+)', result['response'])
                if version_match:
                    output.append(f"[+] ThinkPHP版本: V{version_match.group(1)}")
                
                # 提取错误信息
                if '页面错误' in result['response']:
                    output.append('[+] 响应状态: 成功触发页面错误')
            
            # 异常信息
            if result['exception']:
                output.append(f"[-] 异常信息: {result['exception']}")
            
            return " ".join(output)
            
        except json.JSONDecodeError:
            # 处理非JSON字符串
            return ' '.join(result_str.replace('\\n', ' ').replace('\n', ' ').split())
        except Exception as e:
            return f"结果格式化错误: {str(e)}"

    async def receive(self, text_data):
        try:
            if not text_data:
                await self.send(text_data="错误: URL不能为空")
                return
                
            await self.send(text_data=f"[*] 开始扫描目标: {text_data}")
            
            env = os.environ.copy()
            env['PYTHONPATH'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            cmd = f'"{sys.executable}" "{os.path.join(self.tpscan_dir, "TPscan.py")}" "{text_data}"'
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=self.tpscan_dir,
                env=env,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # 标记是否已显示logo
            logo_shown = False
            logo_buffer = []
            
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                
                line = line.strip()
                if not line:
                    continue
                
                # 处理logo
                if ('___________' in line or 'code by Lucifer' in line or '|_   _|' in line) and not logo_shown:
                    logo_buffer.append(line)
                    if 'code by Lucifer' in line:
                        # 发送完整logo并标记
                        await self.send(text_data='\n'.join(logo_buffer))
                        logo_shown = True
                        logo_buffer = []
                    continue
                elif ('___________' in line or 'code by Lucifer' in line or '|_   _|' in line):
                    continue
                
                # 处理JSON输出
                if line.startswith('{'):
                    try:
                        formatted_output = await self.format_scan_result(line)
                        await self.send(text_data=formatted_output)
                    except Exception as e:
                        logger.error(f"格式化JSON输出错误: {str(e)}")
                        # 如果格式化失败，发送清理过的原始行
                        await self.send(text_data=' '.join(line.replace('\\n', ' ').replace('\n', ' ').split()))
                else:
                    # 清理非JSON输出中的换行符和多余空白
                    cleaned_line = ' '.join(line.replace('\\n', ' ').replace('\n', ' ').split())
                    if cleaned_line:
                        await self.send(text_data=cleaned_line)
            
            # 处理错误输出
            stderr = process.stderr.read()
            if stderr:
                error_msg = ' '.join(stderr.decode('utf-8', errors='replace').replace('\\n', ' ').replace('\n', ' ').split())
                if error_msg:
                    await self.send(text_data=f"[-] 错误: {error_msg}")
            
            # 发送完成消息
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            await self.send(text_data=f"[+] 扫描完成 - {current_time}")
                
        except Exception as e:
            error_msg = f"[-] 执行错误: {str(e)}"
            logger.error(error_msg)
            await self.send(text_data=error_msg)

    async def disconnect(self, close_code):
        logger.info(f"WebSocket连接已断开: {close_code}")

class Struts2Consumer(AsyncWebsocketConsumer):
    # 保存所有活动的进程
    active_processes = set()
    
    @classmethod
    def cleanup_processes(cls):
        """清理所有活动的进程"""
        for process in cls.active_processes.copy():
            try:
                process.terminate()
                process.wait(timeout=1)
            except:
                try:
                    process.kill()
                except:
                    pass
            cls.active_processes.discard(process)

    async def connect(self):
        try:
            await self.accept()
            await self.send(text_data="WebSocket连接成功")
            
            # 获取工具目录路径
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.struts_dir = os.path.join(current_dir, 'tools', 'Struts2-Scan')
            
            # 初始化命令执行进程为None
            self.cmd_process = None
            
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            await self.send(text_data=f"连接错误: {str(e)}")
            await self.close()

    async def receive(self, text_data):
        try:
            # 尝试解析JSON数据
            try:
                data = json.loads(text_data)
            except json.JSONDecodeError:
                data = {'command': text_data}

            if data.get('type') == 'command':
                # 处理命令执行
                await self.handle_command(data.get('command'))
            elif data.get('type') == 'exec':
                # 启动命令执行模式
                await self.start_command_mode(data.get('url'), data.get('vulnName'))
            else:
                # 处理其他请求
                await self.handle_exploit(data)

        except Exception as e:
            error_msg = f"[-] 执行错误: {str(e)}"
            logger.error(error_msg)
            await self.send(text_data=error_msg)

    async def start_command_mode(self, url, vuln_name):
        """启动命令执行模式"""
        try:
            # 如果已有进程在运行，先终止它
            if hasattr(self, 'cmd_process') and self.cmd_process:
                self.cmd_process.terminate()
                try:
                    self.cmd_process.wait(timeout=1)
                except:
                    self.cmd_process.kill()
                self.active_processes.discard(self.cmd_process)
                self.cmd_process = None

            # 构建命令
            cmd = f'"{sys.executable}" "{os.path.join(self.struts_dir, "Struts2Scan.py")}" -u "{url}" -n "{vuln_name}" --exec'
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            env['PYTHONIOENCODING'] = 'gbk'
            
            # 启动进程
            self.cmd_process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=self.struts_dir,
                env=env,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # 添加到活动进程集合
            self.active_processes.add(self.cmd_process)
            
            # 创建一个事件循环来处理输出
            async def read_output():
                while True:
                    line = self.cmd_process.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        await self.send(text_data=line)
                    if '>>>' in line:  # 检测到命令提示符
                        break

            # 读取初始输出
            await read_output()
            
            # 检查错误输出
            stderr = self.cmd_process.stderr.read()
            if stderr:
                error_text = stderr.strip()
                if error_text:
                    await self.send(text_data=f"[-] 错误: {error_text}")

            # 发送提示信息
            await self.send(text_data="\n[+] 命令执行模式已启动，请输入命令")

        except Exception as e:
            await self.send(text_data=f"[-] 启动命令执行模式失败: {str(e)}")
            logger.error(f"启动命令执行模式失败: {str(e)}")
            logger.error(traceback.format_exc())

    async def handle_command(self, command):
        """处理命令执行"""
        if not hasattr(self, 'cmd_process') or not self.cmd_process:
            await self.send(text_data="[-] 命令执行模式未启动")
            return
            
        try:
            # 发送命令到进程
            self.cmd_process.stdin.write(f"{command}\n")
            self.cmd_process.stdin.flush()
            
            # 创建一个事件循环来处理输出
            async def read_command_output():
                output_buffer = []
                while True:
                    line = self.cmd_process.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if '>>>' in line:  # 遇到提示符就停止读取
                        break
                    if line:  # 只发送非空行
                        output_buffer.append(line)
                
                # 发送所有输出
                if output_buffer:
                    await self.send(text_data="\n".join(output_buffer))
                await self.send(text_data=">>>")

            # 读取命令输出
            await read_command_output()
            
            # 检查错误输出
            stderr = self.cmd_process.stderr.read()
            if stderr:
                error_text = stderr.strip()
                if error_text:
                    await self.send(text_data=f"[-] 错误: {error_text}")
                
        except Exception as e:
            await self.send(text_data=f"[-] 命令执行错误: {str(e)}")
            logger.error(f"命令执行错误: {str(e)}")
            logger.error(traceback.format_exc())

    async def handle_exploit(self, data):
        try:
            url = data.get('url')
            vuln_name = data.get('vulnName')
            exploit_type = data.get('type')
            
            if not url or not vuln_name:
                await self.send(text_data="错误: URL和漏洞名称不能为空")
                return
            
            # 构建基础命令
            cmd = f'"{sys.executable}" "{os.path.join(self.struts_dir, "Struts2Scan.py")}" -u "{url}" -n "{vuln_name}"'
            
            # 根据不同的漏洞利用类型添加相应的参数
            if exploit_type == 'exec':
                await self.start_command_mode(url, vuln_name)
                return
            elif exploit_type == 'webpath':
                cmd += ' --webpath'
            elif exploit_type == 'upload':
                shell_path = os.path.join(self.struts_dir, "shell.jsp")
                cmd += f' --upfile "{shell_path}" --uppath "/usr/local/tomcat/webapps/ROOT/shell.jsp"'
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            env['PYTHONIOENCODING'] = 'gbk'  # 修改为GBK编码
            
            # 执行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=self.struts_dir,
                env=env,
                text=False,  # 使用二进制模式
                bufsize=1
            )
            
            # 读取输出并处理编码
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    try:
                        # 首先尝试GBK解码
                        try:
                            decoded_line = line.decode('gbk').strip()
                        except UnicodeDecodeError:
                            # 如果GBK解码失败，尝试UTF-8
                            try:
                                decoded_line = line.decode('utf-8').strip()
                            except UnicodeDecodeError:
                                # 如果都失败，使用gb18030
                                decoded_line = line.decode('gb18030', errors='replace').strip()
                        
                        # 特殊处理文件上传成功的消息
                        if '鏂囦欢涓婁紶鎴愬姛' in decoded_line:
                            decoded_line = decoded_line.replace('鏂囦欢涓婁紶鎴愬姛', '文件上传成功')
                        
                        if decoded_line:
                            await self.send(text_data=decoded_line)
                    except Exception as e:
                        logger.error(f"解码错误: {str(e)}")
            
            # 检查错误输出
            stderr = process.stderr.read()
            if stderr:
                try:
                    try:
                        error_text = stderr.decode('gbk').strip()
                    except UnicodeDecodeError:
                        try:
                            error_text = stderr.decode('utf-8').strip()
                        except UnicodeDecodeError:
                            error_text = stderr.decode('gb18030', errors='replace').strip()
                    
                    if error_text:
                        await self.send(text_data=f"[-] 错误: {error_text}")
                except Exception as e:
                    logger.error(f"解码错误输出时出错: {str(e)}")
            
        except Exception as e:
            error_msg = f"[-] 执行错误: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            await self.send(text_data=error_msg)

    async def disconnect(self, close_code):
        """处理WebSocket断开连接"""
        try:
            # 终止命令执行进程
            if hasattr(self, 'cmd_process') and self.cmd_process:
                self.cmd_process.terminate()
                try:
                    self.cmd_process.wait(timeout=1)
                except:
                    self.cmd_process.kill()
                self.active_processes.discard(self.cmd_process)
                self.cmd_process = None
                
            logger.info(f"WebSocket连接已断开: {close_code}")
        except Exception as e:
            logger.error(f"断开连接时出错: {str(e)}")

# 设置信号处理器
def signal_handler(signum, frame):
    """处理进程终止信号"""
    logger.info("接收到终止信号，正在清理进程...")
    Struts2Consumer.cleanup_processes()
    sys.exit(0)

# 注册信号处理器
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# 注册退出时的清理函数
atexit.register(Struts2Consumer.cleanup_processes)

class SpringScanConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            await self.accept()
            await self.send(text_data="WebSocket连接成功\n")
            
            current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.sbscan_dir = os.path.join(current_dir, 'tools', 'SBSCAN-1.0')
            
            if not os.path.exists(os.path.join(self.sbscan_dir, 'sbscan.py')):
                await self.send(text_data="错误: 未找到sbscan.py文件\n")
                return
                
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            await self.send(text_data=f"连接错误: {str(e)}\n")
            await self.close()

    async def format_scan_result(self, report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                result = json.load(f)
            
            output = []
            output.append("[+] Spring漏洞扫描结果")
            
            if 'found_cves' in result:
                for cve in result['found_cves']:
                    output.append("\n[*] 发现漏洞:")
                    output.append(f"[+] CVE编号: {cve['CVE_ID']}")
                    output.append(f"[+] 目标URL: {cve['URL']}")
                    output.append(f"[+] 漏洞详情: {cve['Details']}")
                    
                    # 处理响应片段，使用红色高亮显示
                    if 'ResponseSnippet' in cve:
                        response = cve['ResponseSnippet']
                        output.append(f'[+] 响应内容: <span style="color: red">{response}</span>')
                    
                    output.append("-" * 50)
            
            return "\n".join(output)
            
        except Exception as e:
            return f"结果格式化错误: {str(e)}"

    async def receive(self, text_data):
        try:
            if not text_data:
                await self.send(text_data="错误: URL不能为空")
                return
                
            await self.send(text_data=f"[*] 开始扫描目标: {text_data}")
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            # 构建命令
            cmd = f'"{sys.executable}" "{os.path.join(self.sbscan_dir, "SBSCAN.py")}" -u "{text_data}"'
            
            # 使用 subprocess.Popen 替代 asyncio.create_subprocess_shell
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                cwd=self.sbscan_dir,
                env=env,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # 等待扫描完成
            process.wait()
            
            # 获取最新的报告文件
            reports_dir = os.path.join(self.sbscan_dir, 'reports')
            if not os.path.exists(reports_dir):
                await self.send(text_data="[-] 未找到报告目录")
                return
            
            report_files = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
            if not report_files:
                await self.send(text_data="[-] 未找到扫描报告")
                return
            
            latest_report = max(report_files, key=lambda x: os.path.getctime(os.path.join(reports_dir, x)))
            report_path = os.path.join(reports_dir, latest_report)
            
            # 读取报告内容
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # 格式化并输出结果
            for result in report_data:
                await self.send(text_data="\n=== 扫描结果 ===")
                await self.send(text_data=f"目标URL: {result.get('url', 'N/A')}")
                
                # 输出检测到的路径
                if result.get('detected_paths'):
                    await self.send(text_data="\n检测到的路径:")
                    for path in result['detected_paths']:
                        await self.send(text_data=f"- {path}")
                
                # 输出发现的CVE
                if result.get('found_cves'):
                    await self.send(text_data="\n发现的CVE:")
                    for cve in result['found_cves']:
                        await self.send(text_data=f"\nCVE ID: {cve.get('CVE_ID', 'N/A')}")
                        await self.send(text_data=f"URL: {cve.get('URL', 'N/A')}")
                        await self.send(text_data=f"详情: {cve.get('Details', 'N/A')}")
                        if cve.get('ResponseSnippet'):
                            await self.send(text_data=f"响应片段: {cve['ResponseSnippet'][:200]}...")
                
                await self.send(text_data="\n=== 扫描完成 ===")
            
            # 发送完成消息
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            await self.send(text_data=f"\n[+] 扫描完成 - {current_time}")
                
        except Exception as e:
            error_msg = f"[-] 执行错误: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            await self.send(text_data=error_msg)

    async def disconnect(self, close_code):
        logger.info(f"WebSocket连接已断开: {close_code}")

    async def scan_url(self, url):
        try:
            # 执行扫描命令
            struts_dir = os.path.join(settings.BASE_DIR, 'tools', 'SBSCAN-1.0')
            cmd = f'"{sys.executable}" "{os.path.join(struts_dir, "SBSCAN.py")}" -u {url}'
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # 等待扫描完成
            await process.wait()
            
            # 获取最新的报告文件
            reports_dir = os.path.join(struts_dir, 'reports')
            report_files = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
            if not report_files:
                await self.send(text_data="未找到扫描报告")
                return
            
            latest_report = max(report_files, key=lambda x: os.path.getctime(os.path.join(reports_dir, x)))
            report_path = os.path.join(reports_dir, latest_report)
            
            # 读取报告内容
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            # 提取并格式化结果
            for result in report_data:
                await self.send(text_data="\n=== 扫描结果 ===")
                await self.send(text_data=f"目标URL: {result.get('url', 'N/A')}")
                
                # 输出检测到的路径
                if result.get('detected_paths'):
                    await self.send(text_data="\n检测到的路径:")
                    for path in result['detected_paths']:
                        await self.send(text_data=f"- {path}")
                
                # 输出发现的CVE
                if result.get('found_cves'):
                    await self.send(text_data="\n发现的CVE:")
                    for cve in result['found_cves']:
                        await self.send(text_data=f"\nCVE ID: {cve.get('CVE_ID', 'N/A')}")
                        await self.send(text_data=f"URL: {cve.get('URL', 'N/A')}")
                        await self.send(text_data=f"详情: {cve.get('Details', 'N/A')}")
                        if cve.get('ResponseSnippet'):
                            await self.send(text_data=f"响应片段: {cve['ResponseSnippet'][:200]}...")
                
                await self.send(text_data="\n=== 扫描完成 ===")
            
        except Exception as e:
            await self.send(text_data=f"错误: {str(e)}")

class LaravelConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.laravel_dir = os.path.join(settings.BASE_DIR, 'tools', 'laravel', 'CVE-2021-3129-exp')

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            url = data.get('url')
            exp_mode = data.get('exp', False)
            
            # 构建命令
            cmd = [
                sys.executable,
                os.path.join(self.laravel_dir, "CVE-2021-3129.py"),
                "-u",
                url
            ]
            
            if exp_mode:
                cmd.append("--exp")
            
            # 直接执行命令并获取输出
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # 合并标准错误到标准输出
                cwd=self.laravel_dir,
                text=False,
                bufsize=1
            )
            
            # 逐行读取并发送输出
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                    
                if line:
                    try:
                        # 尝试GBK解码
                        decoded_line = line.decode('gbk', errors='replace').strip()
                    except UnicodeDecodeError:
                        # 如果失败则尝试UTF-8
                        decoded_line = line.decode('utf-8', errors='replace').strip()
                    
                    if decoded_line:
                        # 直接发送原始输出
                        await self.send(text_data=decoded_line)
            
            # 等待进程结束
            process.wait()
                
        except Exception as e:
            await self.send(text_data=f"Error: {str(e)}")

    async def disconnect(self, close_code):
        pass

class SSTIConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.fenjing_dir = os.path.join(settings.BASE_DIR, 'tools', 'Fenjing-0.7.1')
        
        try:
            # 在后台启动 fenjing webui
            await self.send(text_data="正在启动Fenjing WebUI...")
            
            # 设置环境变量
            env = os.environ.copy()
            env['PYTHONPATH'] = os.path.dirname(os.path.dirname(self.fenjing_dir))
            
            cmd = [sys.executable, '-m', 'fenjing', 'webui', '--port', '11451']
            
            # 使用subprocess.Popen在后台启动进程
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.fenjing_dir,
                text=True,
                encoding='utf-8',
                env=env
            )
            
            # 等待一段时间，确保服务启动
            await asyncio.sleep(2)
            
            # 检查进程是否正常运行
            if process.poll() is None:
                await self.send(text_data="Fenjing WebUI 已成功启动在 http://127.0.0.1:11451")
                await self.send(text_data="请在浏览器中访问 http://127.0.0.1:11451使用SSTI检测工具")
            else:
                stdout, stderr = process.communicate()
                error_msg = stdout or stderr
                await self.send(text_data=f"启动Fenjing WebUI失败: {error_msg}")
            
        except Exception as e:
            error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
            await self.send(text_data=error_msg)

    async def disconnect(self, close_code):
        pass

class PHPGGCConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.phpggc_dir = os.path.join(settings.BASE_DIR, 'tools', 'phpggc-master')
        
        try:
            # 检查phpggc目录是否存在
            if not os.path.exists(self.phpggc_dir):
                await self.send(text_data="错误: 未找到phpggc目录")
                return
                
            await self.send(text_data="WebSocket连接成功")
            
        except Exception as e:
            logger.error(f"连接错误: {str(e)}")
            await self.send(text_data=f"连接错误: {str(e)}")
            await self.close()

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            action = data.get('action')
            
            if action == 'list':
                # 列出所有可用的链
                cmd = ['php', os.path.join(self.phpggc_dir, 'phpggc'), '--list']
            elif action == 'info':
                # 显示特定链的信息
                chain = data.get('chain')
                cmd = ['php', os.path.join(self.phpggc_dir, 'phpggc'), '-i', chain]
            elif action == 'listFramework':
                # 列出特定中间件的所有链
                framework = data.get('framework')
                cmd = ['php', os.path.join(self.phpggc_dir, 'phpggc'), '--list', framework]
            elif action == 'generate':
                # 生成payload
                chain = data.get('chain')
                parameters = data.get('parameters', [])
                cmd = ['php', os.path.join(self.phpggc_dir, 'phpggc'), chain] + parameters
            else:
                await self.send(text_data="错误: 未知的操作类型")
                return
            
            # 执行命令
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=self.phpggc_dir,
                text=True,
                encoding='utf-8'
            )
            
            # 读取输出并进行HTML转义
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    # 对输出进行HTML转义
                    escaped_line = html.escape(line.strip())
                    await self.send(text_data=escaped_line)
            
            # 检查错误
            if process.returncode != 0:
                await self.send(text_data=f"命令执行失败，返回码: {process.returncode}")
                
        except json.JSONDecodeError:
            await self.send(text_data="错误: 无效的JSON数据")
        except Exception as e:
            error_msg = f"执行错误: {str(e)}"
            logger.error(error_msg)
            await self.send(text_data=error_msg)

    async def disconnect(self, close_code):
        pass