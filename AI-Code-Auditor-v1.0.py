#coding:utf-8
import os
import re
import json
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import configparser
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import time
import traceback
from typing import List, Dict, Tuple, Optional, Set

# 配置日志
def setup_logger():
    logger = logging.getLogger('AICodeAuditor')
    logger.setLevel(logging.DEBUG)
    
    # 确保日志目录存在
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # 限制日志文件大小为5MB，保留3个备份
    handler = RotatingFileHandler(
        'logs/audit.log', 
        maxBytes=5*1024*1024, 
        backupCount=3,
        encoding='utf-8'
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
    
    # 控制台输出DEBUG级别日志
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logger()

class RuleIntegration:
    """规则集成与管理类，负责处理白名单和污染模式检测"""
    def __init__(self):
        self.whitelist = set()
        self.taint_patterns = {}  # 初始化污染模式字典
        self.load_default_whitelist()
        
    def load_default_whitelist(self):
        """加载默认白名单模式"""
        self.whitelist = {
            r'^test_.*\.py$',  # 测试文件
            r'^docs[\\/].*$',      # 文档目录（兼容Windows和Linux路径）
            r'^vendor[\\/].*$',    # 第三方依赖
            r'^\.git[\\/].*$',     # Git版本控制目录
            r'^__pycache__[\\/].*$' # Python缓存目录
        }
        
    def is_in_whitelist(self, file_path: str) -> bool:
        """检查文件是否在白名单中（修复路径匹配问题）"""
        if not file_path:
            return False
            
        # 统一路径分隔符为/，便于正则匹配
        normalized_path = file_path.replace(os.sep, '/')
        for pattern in self.whitelist:
            if re.match(pattern, normalized_path, re.IGNORECASE):
                return True
        return False
    
    def import_from_json(self, file_path: str) -> bool:
        """从JSON文件导入规则（修复规则处理逻辑）"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"规则文件不存在: {file_path}")
                return False
                
            with open(file_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            if not isinstance(rules, list):
                logger.error("导入的规则格式不正确，应为列表类型")
                return False
                
            # 实际处理导入的规则
            added = 0
            for rule in rules:
                if isinstance(rule, dict) and 'lang' in rule and 'pattern' in rule and 'description' in rule:
                    if rule['lang'] not in self.taint_patterns:
                        self.taint_patterns[rule['lang']] = {}
                    self.taint_patterns[rule['lang']][rule['pattern']] = rule['description']
                    added += 1
            
            logger.info(f"成功导入 {added} 条有效规则")
            return True
        except json.JSONDecodeError:
            logger.error(f"规则文件格式错误，不是有效的JSON: {file_path}")
            return False
        except Exception as e:
            logger.error(f"导入规则失败: {str(e)}")
            return False
    
    def has_tainted_flow(self, code: str, lang: str) -> List[Dict]:
        """检测代码中的污染数据流，返回标准化的结果格式"""
        results = []
        if lang in self.taint_patterns and self.taint_patterns[lang]:
            for pattern, desc in self.taint_patterns[lang].items():
                try:
                    matches = re.finditer(pattern, code, re.MULTILINE)
                    for match in matches:
                        line_number = code.count('\n', 0, match.start()) + 1
                        results.append({
                            "file": "",  # 后续会被填充
                            "vulnerability": "污染数据流",
                            "severity": "中危",
                            "line": line_number,
                            "description": desc,
                            "recommendation": "检查输入验证和净化逻辑",
                            "code_snippet": ""  # 后续会被填充
                        })
                except re.error as e:
                    logger.error(f"正则表达式错误 in 规则 '{pattern}': {str(e)}")
        return results

class AICodeAuditor:
    """多语言代码审计工具主类，负责协调所有审计功能和UI交互"""
    def __init__(self, root):
        self.root = root
        self.root.title("信安西部-明镜高悬实验室-AICodeAuditor（v1.0）")
        self.root.geometry("1200x800")
        # 确保窗口关闭时正确退出线程
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # 配置初始化
        self.config = self._init_config()
        self.api_key = self._decrypt_key(self.config.get('API', 'key', fallback=''))
        self.api_endpoint = self.config.get('API', 'endpoint', fallback='https://api.deepseek.com/v1/audit')
        
        # 状态控制（添加线程锁确保线程安全）
        self.scanning = False
        self.paused = False
        self.lock = threading.Lock()
        self.event_queue = queue.Queue()
        self.max_recursion_depth = int(self.config.get('Settings', 'recursion_depth', fallback='20'))
        self.large_file_threshold = int(self.config.get('Settings', 'large_file_threshold', fallback='10')) * 1024 * 1024  # MB转字节
        
        # 规则与插件系统
        self.rule_integrator = RuleIntegration()
        self.audit_rules = self._init_audit_rules()
        self.compiled_rules = {}  # 预编译的正则规则缓存
        self._precompile_rules()  # 预编译所有规则
        self.plugins = self._load_plugins()
        self.audit_results = []  # 确保初始化结果列表
        
        # UI组件
        self._create_ui()
        
        # 启动事件处理器
        self._start_event_processor()
    
    def _precompile_rules(self):
        """预编译所有正则规则以提高性能"""
        self.compiled_rules = {}
        for lang, rules in self.audit_rules.items():
            self.compiled_rules[lang] = []
            for rule in rules:
                try:
                    # 预编译正则表达式并缓存
                    compiled = re.compile(rule['pattern'], re.IGNORECASE | re.MULTILINE)
                    # 保留原始规则信息并替换为编译后的模式
                    self.compiled_rules[lang].append({** rule, 'pattern': compiled})
                except re.error as e:
                    logger.error(f"正则表达式错误 in {rule['vulnerability']}: {str(e)}")
        
    def _init_config(self) -> configparser.ConfigParser:
        """初始化配置系统"""
        config = configparser.ConfigParser()
        config_path = 'AICodeAuditor.ini'
        
        if not os.path.exists(config_path):
            config['API'] = {'key': '', 'endpoint': 'https://api.deepseek.com/v1/audit'}
            config['Settings'] = {
                'max_threads': '4',
                'large_file_threshold': '10',  # MB
                'recursion_depth': '20'
            }
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    config.write(f)
            except Exception as e:
                logger.error(f"创建配置文件失败: {str(e)}")
        
        try:
            config.read(config_path, encoding='utf-8')
        except Exception as e:
            logger.error(f"读取配置文件失败: {str(e)}")
        return config
    
    def _encrypt_key(self, key: str) -> str:
        """简单加密API密钥"""
        if not key:
            return ""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _decrypt_key(self, encrypted_key: str) -> str:
        """解密API密钥（实际使用时建议用可逆加密）"""
        return encrypted_key  # 演示用，实际需改为可逆解密
    
    def _init_audit_rules(self) -> Dict[str, List[Dict]]:
        """初始化审计规则库（支持多种语言和规则）"""
        return {
            'python': [
                {
                    'pattern': r'request\.args\.[get|getlist]',
                    'vulnerability': '潜在SQL注入',
                    'severity': '中危',
                    'description': '直接使用请求参数可能导致SQL注入',
                    'recommendation': '使用参数化查询或ORM框架'
                },
                {
                    'pattern': r'eval\(',
                    'vulnerability': '代码注入风险',
                    'severity': '高危',
                    'description': 'eval函数执行字符串为代码，存在注入风险',
                    'recommendation': '避免使用eval，改用安全的替代方案'
                },
                {
                    'pattern': r'os\.system\(',
                    'vulnerability': '命令注入风险',
                    'severity': '高危',
                    'description': '直接使用os.system执行包含用户输入的命令',
                    'recommendation': '使用subprocess.run并指定shell=False，或严格验证输入'
                },
                {
                    'pattern': r'pickle\.load\(',
                    'vulnerability': '反序列化漏洞',
                    'severity': '高危',
                    'description': '使用pickle加载不可信数据可能导致远程代码执行',
                    'recommendation': '避免反序列化不可信数据，使用更安全的序列化格式'
                },
                {
                    'pattern': r'open\(.*user_input.*\)',
                    'vulnerability': '路径遍历风险',
                    'severity': '中危',
                    'description': '使用用户输入直接构造文件路径可能导致路径遍历',
                    'recommendation': '验证并净化用户输入的路径，使用绝对路径'
                }
            ],
            'javascript': [
                {
                    'pattern': r'document\.write\(.*userInput.*\)',
                    'vulnerability': 'XSS漏洞',
                    'severity': '高危',
                    'description': '直接输出用户输入可能导致XSS攻击',
                    'recommendation': '使用textContent或适当的转义函数'
                },
                {
                    'pattern': r'eval\(',
                    'vulnerability': '代码注入风险',
                    'severity': '高危',
                    'description': '使用eval执行动态代码存在安全风险',
                    'recommendation': '避免使用eval，改用其他安全的解析方式'
                },
                {
                    'pattern': r'innerHTML\s*=',
                    'vulnerability': 'XSS漏洞',
                    'severity': '高危',
                    'description': '直接设置innerHTML可能导致跨站脚本攻击',
                    'recommendation': '优先使用textContent，必须使用时需进行HTML转义'
                },
                {
                    'pattern': r'new Function\(',
                    'vulnerability': '代码注入风险',
                    'severity': '高危',
                    'description': '使用new Function创建函数可能执行恶意代码',
                    'recommendation': '避免使用动态创建函数，或严格验证输入'
                }
            ],
            'java': [
                {
                    'pattern': r'Statement\s*\..*execute\(',
                    'vulnerability': 'SQL注入风险',
                    'severity': '高危',
                    'description': '使用Statement执行拼接的SQL语句存在注入风险',
                    'recommendation': '使用PreparedStatement进行参数化查询'
                },
                {
                    'pattern': r'Runtime\.getRuntime\(\)\.exec\(',
                    'vulnerability': '命令注入风险',
                    'severity': '高危',
                    'description': '执行包含用户输入的系统命令存在注入风险',
                    'recommendation': '避免执行系统命令，必须使用时需严格验证输入'
                },
                {
                    'pattern': r'FileInputStream\(.*request\..*\)',
                    'vulnerability': '路径遍历风险',
                    'severity': '中危',
                    'description': '使用用户输入直接构造文件路径可能导致未授权文件访问',
                    'recommendation': '验证用户输入，使用基于白名单的文件访问控制'
                }
            ],
            'php': [
                {
                    'pattern': r'mysql_query\(',
                    'vulnerability': 'SQL注入风险',
                    'severity': '高危',
                    'description': '使用mysql_query执行拼接SQL存在注入风险',
                    'recommendation': '使用PDO预处理语句或mysqli prepared statements'
                },
                {
                    'pattern': r'eval\(',
                    'vulnerability': '代码注入风险',
                    'severity': '高危',
                    'description': 'PHP eval函数执行字符串为代码，存在严重安全风险',
                    'recommendation': '完全避免使用eval函数处理任何用户输入'
                },
                {
                    'pattern': r'include\(|require\(',
                    'vulnerability': '文件包含漏洞',
                    'severity': '高危',
                    'description': '使用用户输入动态包含文件可能导致远程代码执行',
                    'recommendation': '避免动态包含文件，或使用严格的白名单验证'
                },
                {
                    'pattern': r'echo\s+(\$_GET|\$_POST|\$_REQUEST)',
                    'vulnerability': 'XSS漏洞',
                    'severity': '中危',
                    'description': '直接输出用户输入数据可能导致跨站脚本攻击',
                    'recommendation': '使用htmlspecialchars()等函数进行输出编码'
                }
            ],
            'c': [
                {
                    'pattern': r'printf\(.*%s.*user_input.*\)',
                    'vulnerability': '格式化字符串漏洞',
                    'severity': '高危',
                    'description': '使用用户输入作为printf格式字符串存在安全风险',
                    'recommendation': '确保格式字符串为常量，用户输入作为参数传递'
                },
                {
                    'pattern': r'strcpy\(',
                    'vulnerability': '缓冲区溢出风险',
                    'severity': '高危',
                    'description': 'strcpy不检查目标缓冲区大小，可能导致溢出',
                    'recommendation': '使用更安全的strncpy或其他边界检查函数'
                },
                {
                    'pattern': r'system\(',
                    'vulnerability': '命令注入风险',
                    'severity': '高危',
                    'description': '使用用户输入构造系统命令存在注入风险',
                    'recommendation': '避免执行系统命令，必须使用时需严格验证输入'
                }
            ],
            'c++': [
                {
                    'pattern': r'cin\s*>>\s*',
                    'vulnerability': '缓冲区溢出风险',
                    'severity': '高危',
                    'description': '使用cin直接读取输入可能导致缓冲区溢出',
                    'recommendation': '使用带长度限制的输入方法，并验证输入长度'
                },
                {
                    'pattern': r'gets\(',
                    'vulnerability': '缓冲区溢出风险',
                    'severity': '高危',
                    'description': 'gets函数不检查输入长度，存在严重溢出风险',
                    'recommendation': '使用fgets并指定最大长度'
                },
                {
                    'pattern': r'std::string::c_str\(\)\s*,\s*system\(',
                    'vulnerability': '命令注入风险',
                    'severity': '高危',
                    'description': '将字符串直接传递给system函数存在命令注入风险',
                    'recommendation': '避免使用system，必须使用时需严格验证输入'
                }
            ],
            'go': [
                {
                    'pattern': r'os\.Exec\(',
                    'vulnerability': '命令注入风险',
                    'severity': '高危',
                    'description': '使用字符串构造命令参数存在注入风险',
                    'recommendation': '使用带参数列表的Exec形式，如os.Exec("cmd", []string{"arg1"})'
                },
                {
                    'pattern': r'database/sql\.Query\(.*userInput.*\)',
                    'vulnerability': 'SQL注入风险',
                    'severity': '中危',
                    'description': '直接拼接SQL查询字符串存在注入风险',
                    'recommendation': '使用参数化查询，如db.Query("SELECT * FROM t WHERE id=?", id)'
                }
            ],
            'ruby': [
                {
                    'pattern': r'eval\(',
                    'vulnerability': '代码注入风险',
                    'severity': '高危',
                    'description': 'Ruby eval函数执行字符串为代码，存在注入风险',
                    'recommendation': '避免使用eval处理用户输入，使用更安全的替代方法'
                },
                {
                    'pattern': r'ActiveRecord::Base\.connection\.execute\(.*params.*\)',
                    'vulnerability': 'SQL注入风险',
                    'severity': '高危',
                    'description': '直接执行拼接的SQL语句存在注入风险',
                    'recommendation': '使用ActiveRecord的参数化查询功能'
                }
            ],
            'html': [
                {
                    'pattern': r'<script>.*<%=.*%>.*</script>',
                    'vulnerability': 'XSS漏洞',
                    'severity': '高危',
                    'description': '在脚本标签中直接输出未转义的变量',
                    'recommendation': '使用适当的模板转义函数，避免在脚本中直接使用变量'
                },
                {
                    'pattern': r'<a\s+href="javascript:.*<%=.*%>">',
                    'vulnerability': 'XSS漏洞',
                    'severity': '中危',
                    'description': '在javascript伪协议中使用未转义的变量',
                    'recommendation': '避免使用javascript伪协议，或对变量进行严格转义'
                }
            ]
        }
    
    def _load_plugins(self) -> List[Dict]:
        """加载并验证插件"""
        plugins = []
        plugin_dir = 'plugins'
        
        try:
            if not os.path.exists(plugin_dir):
                os.makedirs(plugin_dir)
                return plugins
                
            for file in os.listdir(plugin_dir):
                if file.endswith('.py') and not file.startswith('_'):
                    plugin_path = os.path.join(plugin_dir, file)
                    plugins.append({'name': file, 'path': plugin_path})
                    logger.info(f"加载插件: {file}")
        except Exception as e:
            logger.error(f"加载插件失败: {str(e)}")
        
        return plugins
    
    def _create_ui(self):
        """创建用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 5))
        
        # 工具栏按钮
        ttk.Button(toolbar, text="选择项目", command=self._select_project).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="开始审计", command=self._start_audit).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="暂停", command=self._pause_audit).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="停止", command=self._stop_audit).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="导入规则", command=self._import_rules).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="导出报告", command=self._export_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="API设置", command=self._configure_api).pack(side=tk.LEFT, padx=2)
        
        # 分割窗格
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # 左侧文件树
        file_frame = ttk.LabelFrame(paned_window, text="项目文件")
        paned_window.add(file_frame, weight=1)
        
        self.file_tree = ttk.Treeview(file_frame)
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar_y = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x = ttk.Scrollbar(file_frame, orient=tk.HORIZONTAL, command=self.file_tree.xview)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.file_tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        
        # 右侧结果区域
        result_frame = ttk.LabelFrame(paned_window, text="审计结果")
        paned_window.add(result_frame, weight=2)
        
        # 结果表格 - 使用中文列名
        columns = ('file', 'vulnerability', 'severity', 'line')
        self.result_tree = ttk.Treeview(result_frame, columns=columns, show='headings')

        # 定义中文列名映射
        column_names = {
            'file': '文件路径',
            'vulnerability': '漏洞类型',
            'severity': '风险等级',
            'line': '代码行号'
        }

        for col in columns:
            self.result_tree.heading(col, text=column_names[col])  # 使用中文列名
            width = 250 if col == 'file' else 150 if col == 'vulnerability' else 80 if col == 'severity' else 50
            self.result_tree.column(col, width=width, anchor=tk.W)
        
        # 结果表格滚动条
        tree_scroll_y = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=self.result_tree.xview)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.result_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        self.result_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.result_tree.bind('<<TreeviewSelect>>', self._show_vulnerability_details)
        
        # 详情展示区
        details_frame = ttk.LabelFrame(result_frame, text="漏洞详情")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        self.details_text.config(state=tk.DISABLED)
        
        # 进度条和状态栏
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(progress_frame, textvariable=self.status_var).pack(side=tk.RIGHT, padx=5)
    
    def _start_event_processor(self):
        """启动事件处理器线程，处理UI更新事件"""
        def process_events():
            while True:
                try:
                    event = self.event_queue.get(timeout=1)  # 超时避免无限阻塞
                    if event['type'] == 'update_status':
                        self.status_var.set(event['message'])
                    elif event['type'] == 'update_progress':
                        self.progress_var.set(event['value'])
                    elif event['type'] == 'add_result':
                        self._add_result_to_tree(event['data'])
                    elif event['type'] == 'scan_complete':
                        with self.lock:
                            self.scanning = False
                        self.status_var.set("审计完成")
                    elif event['type'] == 'error':
                        messagebox.showerror("错误", event['message'])
                        logger.error(event['message'])
                    self.event_queue.task_done()
                except queue.Empty:
                    continue
                except Exception as e:
                    logger.error(f"事件处理错误: {str(e)}")
                    continue
        
        thread = threading.Thread(target=process_events, daemon=True)
        thread.start()
    
    def _select_project(self):
        """选择项目目录并在文件树中显示"""
        project_dir = filedialog.askdirectory(title="选择项目目录")
        if project_dir and os.path.isdir(project_dir):
            self.project_dir = project_dir
            self.file_tree.delete(*self.file_tree.get_children())
            root_node = self.file_tree.insert('', tk.END, text=os.path.basename(project_dir), open=True)
            self._add_files_to_tree(root_node, project_dir, current_depth=0)
            self.status_var.set(f"已选择项目: {project_dir}")
        elif project_dir:
            messagebox.showerror("错误", f"所选路径不是有效的目录: {project_dir}")
    
    def _add_files_to_tree(self, parent_node, directory, current_depth):
        """递归添加文件到树状视图（限制深度）"""
        if current_depth >= self.max_recursion_depth:
            self.file_tree.insert(parent_node, tk.END, text="... (超出最大深度)")
            return
            
        try:
            # 按名称排序文件和目录，目录在前
            items = os.listdir(directory)
            dirs = sorted([item for item in items if os.path.isdir(os.path.join(directory, item))])
            files = sorted([item for item in items if os.path.isfile(os.path.join(directory, item))])
            
            for item in dirs + files:
                item_path = os.path.join(directory, item)
                # 使用相对路径进行白名单检查
                rel_path = os.path.relpath(item_path, self.project_dir)
                if self.rule_integrator.is_in_whitelist(rel_path):
                    continue
                    
                node = self.file_tree.insert(parent_node, tk.END, text=item)
                if os.path.isdir(item_path):
                    self._add_files_to_tree(node, item_path, current_depth + 1)
        except PermissionError:
            self.file_tree.insert(parent_node, tk.END, text=f"{item} (无权限)")
        except Exception as e:
            logger.warning(f"添加文件到树失败: {str(e)}")
    
    def _start_audit(self):
        """开始审计过程，初始化并启动审计线程"""
        with self.lock:
            if self.scanning:
                messagebox.showinfo("提示", "审计已在进行中")
                return
                
            if not hasattr(self, 'project_dir') or not os.path.isdir(self.project_dir):
                messagebox.showwarning("警告", "请先选择有效的项目目录")
                return
                
            self.scanning = True
            self.paused = False
        
        self.result_tree.delete(*self.result_tree.get_children())
        self.audit_results = []  # 重置结果列表
        
        # 获取所有文件路径
        files = []
        try:
            for root, _, file_names in os.walk(self.project_dir):
                for file_name in file_names:
                    file_path = os.path.join(root, file_name)
                    rel_path = os.path.relpath(file_path, self.project_dir)
                    if not self.rule_integrator.is_in_whitelist(rel_path):
                        files.append(file_path)
        except Exception as e:
            messagebox.showerror("错误", f"获取文件列表失败: {str(e)}")
            with self.lock:
                self.scanning = False
            return
        
        if not files:
            messagebox.showinfo("提示", "未找到符合条件的文件")
            with self.lock:
                self.scanning = False
            return
        
        # 显示文件数量信息
        messagebox.showinfo("开始审计", f"将审计 {len(files)} 个文件")
        
        # 启动审计线程
        self.total_files = len(files)
        self.processed_files = 0
        self.progress_var.set(0)
        
        audit_thread = threading.Thread(
            target=self._perform_audit,
            args=(files,),
            daemon=True
        )
        audit_thread.start()
    
    def _pause_audit(self):
        """暂停/继续审计"""
        with self.lock:
            if not self.scanning:
                return
                
            self.paused = not self.paused
            status = "已暂停" if self.paused else "继续审计中"
            self.event_queue.put({'type': 'update_status', 'message': status})
    
    def _stop_audit(self):
        """停止审计"""
        with self.lock:
            self.scanning = False
            self.paused = False
        self.event_queue.put({'type': 'update_status', 'message': "审计已停止"})
    
    def _get_language(self, file_path: str) -> Optional[str]:
        """根据文件扩展名判断编程语言"""
        ext = os.path.splitext(file_path)[1].lower()
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.html': 'html',
            '.htm': 'html',
            '.java': 'java',
            '.php': 'php',
            '.cpp': 'c++',
            '.c': 'c',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.m': 'objective-c',
            '.scala': 'scala',
            '.pl': 'perl',
            '.sh': 'shell'
        }
        return ext_map.get(ext)
    
    def _rule_based_detection(self, code: str, file_path: str, lang: str) -> List[Dict]:
        """基于规则的漏洞检测，使用预编译的正则表达式提高性能"""
        results = []
        if lang not in self.compiled_rules:
            return results
            
        for rule in self.compiled_rules[lang]:
            try:
                matches = rule['pattern'].finditer(code)
                
                for match in matches:
                    # 获取匹配行号
                    line_number = code.count('\n', 0, match.start()) + 1
                    
                    result = {
                        'file': file_path,
                        'vulnerability': rule['vulnerability'],
                        'severity': rule['severity'],
                        'line': line_number,
                        'description': rule['description'],
                        'recommendation': rule['recommendation'],
                        'code_snippet': self._get_code_snippet(code, line_number)
                    }
                    results.append(result)
            except re.error as e:
                logger.error(f"正则表达式错误 in {rule['vulnerability']}: {str(e)}")
        
        return results
    
    def _get_code_snippet(self, code: str, line_number: int, context_lines: int = 3) -> str:
        """获取代码片段（包含上下文）"""
        lines = code.split('\n')
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        snippet = []
        for i in range(start, end):
            line_num = i + 1
            marker = '->' if line_num == line_number else '  '
            snippet.append(f"{marker} {line_num}: {lines[i][:100]}")  # 限制单行长度
            
        return '\n'.join(snippet)
    
    def _api_based_detection(self, code: str, file_path: str, lang: str) -> List[Dict]:
        """基于真实API的增强检测（返回实际漏洞类型）"""
        results = []
        if not self.api_key or not self.api_endpoint:
            logger.warning("API密钥或端点未配置，跳过API检测")
            return results
            
        try:
            logger.info(f"对 {file_path} 进行API增强检测")
            
            # 1. 准备调用API的参数
            import requests
            payload = {
                "code": code,           # 待检测的代码
                "language": lang,       # 代码语言
                "filename": os.path.basename(file_path)  # 文件名
            }
            
            # 2. 调用DeepSeek API（请替换为实际接口文档中的参数）
            response = requests.post(
                url=self.api_endpoint,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=30  # 超时时间30秒
            )
            
            # 3. 处理API返回结果（根据实际接口响应格式调整）
            if response.status_code == 200:
                api_result = response.json()
                
                # 假设API返回格式为：{"vulnerabilities": [{"type": "...", "line": 123, ...}]}
                for vuln in api_result.get("vulnerabilities", []):
                    # 提取API返回的真实漏洞类型和信息
                    results.append({
                        'file': file_path,
                        'vulnerability': vuln.get("type", "API检测到的潜在漏洞"),
                        'severity': vuln.get("severity", "中危"),
                        'line': vuln.get("line", self._get_risky_line(code, lang)),  # 优先用API返回的行号
                        'description': vuln.get("description", "API分析发现潜在漏洞"),
                        'recommendation': vuln.get("recommendation", "请参考API详细建议"),
                        'code_snippet': self._get_code_snippet(code, vuln.get("line", 1))
                    })
            else:
                logger.error(f"API调用失败，状态码: {response.status_code}，响应: {response.text}")
                
            return results
        except Exception as e:
            logger.error(f"API检测失败: {str(e)}")
            return results

    def _get_risky_line(self, code: str, lang: str) -> int:
        """辅助函数：当API未返回行号时，自动分析风险行（复用之前的逻辑）"""
        lines = code.split('\n')
        risk_keywords = {
            'python': ['eval', 'exec', 'os.system'],
            'javascript': ['eval', 'innerHTML'],
            'java': ['Statement.execute', 'Runtime.exec'],
            'php': ['eval', 'mysql_query'],
            'c': ['strcpy', 'system'],
            'go': ['os.Exec', 'database/sql.Query']
        }
        keywords = risk_keywords.get(lang, [])
        for line_num, line in enumerate(lines, 1):
            if any(keyword in line for keyword in keywords):
                return line_num
        return max(1, len(lines) // 2)  # 无风险行时返回中间行
    
    def _perform_audit(self, files: List[str]):
        """执行审计（多线程处理）"""
        try:
            max_threads = int(self.config.get('Settings', 'max_threads', fallback='4'))
            max_threads = max(1, min(16, max_threads))  # 限制线程数在合理范围
            thread_pool = []
            
            # 按批次处理文件
            batch_size = max(1, len(files) // max_threads)
            
            for i in range(0, len(files), batch_size):
                with self.lock:
                    if not self.scanning:
                        break
                        
                batch = files[i:i+batch_size]
                thread = threading.Thread(
                    target=self._process_file_batch,
                    args=(batch,),
                    daemon=True
                )
                thread_pool.append(thread)
                thread.start()
                
                # 控制并发数
                while len([t for t in thread_pool if t.is_alive()]) >= max_threads:
                    time.sleep(0.1)
                    with self.lock:
                        if not self.scanning:
                            break
            
            # 等待所有线程完成
            for thread in thread_pool:
                if thread.is_alive():
                    thread.join(5)  # 超时防止无限等待
            
            self.event_queue.put({'type': 'scan_complete'})
            
        except Exception as e:
            error_msg = f"审计过程出错: {str(e)}\n{traceback.format_exc()}"
            self.event_queue.put({'type': 'error', 'message': error_msg})
            with self.lock:
                self.scanning = False
    
    def _process_file_batch(self, batch: List[str]):
        """处理文件批次，根据文件大小采用不同处理策略"""
        for file_path in batch:
            with self.lock:
                if not self.scanning:
                    break
                    
                # 处理暂停状态
                while self.paused and self.scanning:
                    time.sleep(0.5)
        
            try:
                # 获取文件大小并决定处理策略
                file_size = os.path.getsize(file_path)
                
                # 过滤大文件
                if file_size > self.large_file_threshold:
                    logger.info(f"跳过大型文件: {file_path}")
                    self._update_progress()
                    continue
                
                # 判断文件类型
                lang = self._get_language(file_path)
                if not lang:
                    self._update_progress()
                    continue
                
                # 对于中等大小文件（1MB到large_file_threshold），按块处理
                if file_size > 1 * 1024 * 1024:  # 1MB
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        results = []
                        # 跟踪当前读取到的位置（行号计算用）
                        current_position = 0
                        # 按块处理
                        while True:
                            chunk = f.read(1024*1024)  # 1MB块
                            if not chunk:
                                break
                                
                            # 执行检测
                            chunk_results = self._rule_based_detection(chunk, file_path, lang)
                            # 调整行号（加上之前已读取的行数）
                            lines_before = current_position.count('\n')
                            for result in chunk_results:
                                result['line'] += lines_before
                            results.extend(chunk_results)
                            
                            # 更新当前位置
                            current_position += chunk
                        
                        # 处理污染数据流检测
                        taint_results = self.rule_integrator.has_tainted_flow(current_position, lang)
                        for result in taint_results:
                            result['file'] = file_path
                            result['code_snippet'] = self._get_code_snippet(current_position, result['line'])
                        results.extend(taint_results)
                        
                        # 如果配置了API，执行增强检测
                        if self.api_key and self.api_endpoint:
                            results.extend(self._api_based_detection(current_position, file_path, lang))
                        
                        # 发送结果到UI
                        for result in results:
                            self.event_queue.put({'type': 'add_result', 'data': result})
                            with self.lock:
                                self.audit_results.append(result)
                else:
                    # 正常处理小文件
                    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        code = f.read()
                        
                    # 执行检测
                    results = []
                    results.extend(self._rule_based_detection(code, file_path, lang))
                    
                    # 处理污染数据流检测
                    taint_results = self.rule_integrator.has_tainted_flow(code, lang)
                    for result in taint_results:
                        result['file'] = file_path
                        result['code_snippet'] = self._get_code_snippet(code, result['line'])
                    results.extend(taint_results)
                    
                    # 如果配置了API，执行增强检测
                    if self.api_key and self.api_endpoint:
                        results.extend(self._api_based_detection(code, file_path, lang))
                    
                    # 发送结果到UI
                    for result in results:
                        self.event_queue.put({'type': 'add_result', 'data': result})
                        with self.lock:
                            self.audit_results.append(result)
                            
            except Exception as e:
                error_msg = f"处理文件 {os.path.basename(file_path)} 时出错: {str(e)}"
                self.event_queue.put({'type': 'error', 'message': error_msg})
            finally:
                self._update_progress()
    
    def _update_progress(self):
        """更新进度条和状态信息"""
        with self.lock:
            self.processed_files += 1
            progress = (self.processed_files / self.total_files) * 100 if self.total_files > 0 else 0
            self.event_queue.put({
                'type': 'update_progress',
                'value': progress
            })
            self.event_queue.put({
                'type': 'update_status', 
                'message': f"已处理 {self.processed_files}/{self.total_files} 个文件"
            })
    
    def _add_result_to_tree(self, result: Dict):
        """添加结果到表格"""
        # 只显示相对于项目目录的路径，避免路径过长
        if hasattr(self, 'project_dir'):
            display_path = os.path.relpath(result['file'], self.project_dir)
        else:
            display_path = result['file']
            
        self.result_tree.insert('', tk.END, values=(
            display_path,
            result['vulnerability'],
            result['severity'],
            result['line']
        ))
    
    def _show_vulnerability_details(self, event):
        """显示漏洞详情"""
        selected = self.result_tree.selection()
        if not selected:
            return
            
        item = selected[0]
        display_path = self.result_tree.item(item, 'values')[0]
        vulnerability = self.result_tree.item(item, 'values')[1]
        
        # 查找对应的详细信息
        full_path = display_path
        if hasattr(self, 'project_dir'):
            full_path = os.path.join(self.project_dir, display_path)
            
        for result in self.audit_results:
            if result['file'] == full_path and result['vulnerability'] == vulnerability:
                self.details_text.config(state=tk.NORMAL)
                self.details_text.delete(1.0, tk.END)
                details = (
                    f"文件: {result['file']}\n"
                    f"漏洞类型: {result['vulnerability']}\n"
                    f"风险等级: {result['severity']}\n"
                    f"行号: {result['line']}\n\n"
                    f"描述:\n{result['description']}\n\n"
                    f"修复建议:\n{result['recommendation']}\n\n"
                    f"代码片段:\n{result['code_snippet']}"
                )
                self.details_text.insert(tk.END, details)
                self.details_text.config(state=tk.DISABLED)
                break
    
    def _export_report(self):
        """导出审计报告"""
        if not self.audit_results:
            messagebox.showinfo("提示", "没有审计结果可导出")
            return
            
        export_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if export_path:
            try:
                # 根据扩展名选择导出格式
                if export_path.endswith('.json'):
                    with open(export_path, 'w', encoding='utf-8') as f:
                        json.dump(self.audit_results, f, ensure_ascii=False, indent=2)
                else:
                    with open(export_path, 'w', encoding='utf-8') as f:
                        f.write("AICodeAuditor 审计报告\n")
                        f.write(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"项目路径: {getattr(self, 'project_dir', '未知')}\n")
                        f.write(f"发现漏洞: {len(self.audit_results)}\n\n")
                        
                        for i, result in enumerate(self.audit_results, 1):
                            f.write(f"[{i}] {result['vulnerability']} ({result['severity']})\n")
                            f.write(f"文件: {result['file']} 行号: {result['line']}\n")
                            f.write(f"描述: {result['description']}\n")
                            f.write(f"建议: {result['recommendation']}\n\n")
                
                messagebox.showinfo("成功", f"报告已导出至: {export_path}")
                logger.info(f"审计报告导出成功: {export_path}")
            except Exception as e:
                messagebox.showerror("错误", f"导出报告失败: {str(e)}")
                logger.error(f"导出报告失败: {str(e)}")
    
    def _configure_api(self):
        """配置API设置"""
        dialog = tk.Toplevel(self.root)
        dialog.title("API设置")
        dialog.geometry("450x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="API密钥:").pack(anchor=tk.W, padx=20, pady=(20, 5))
        api_key_var = tk.StringVar(value=self.api_key)
        api_key_entry = ttk.Entry(dialog, textvariable=api_key_var, show='*')
        api_key_entry.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        ttk.Label(dialog, text="API端点:").pack(anchor=tk.W, padx=20, pady=(10, 5))
        endpoint_var = tk.StringVar(value=self.api_endpoint)
        endpoint_entry = ttk.Entry(dialog, textvariable=endpoint_var)
        endpoint_entry.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        def save_settings():
            self.api_key = api_key_var.get()
            self.api_endpoint = endpoint_var.get()
            
            # 保存配置
            self.config['API']['key'] = self._encrypt_key(self.api_key)
            self.config['API']['endpoint'] = self.api_endpoint
            
            try:
                with open('AICodeAuditor.ini', 'w', encoding='utf-8') as f:
                    self.config.write(f)
                messagebox.showinfo("成功", "API设置已保存")
            except Exception as e:
                messagebox.showerror("错误", f"保存设置失败: {str(e)}")
                
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Button(button_frame, text="保存", command=save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="取消", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
    
    def _import_rules(self):
        """导入规则文件"""
        file_path = filedialog.askopenfilename(
            title="选择规则JSON文件",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if file_path:
            if self.rule_integrator.import_from_json(file_path):
                messagebox.showinfo("成功", "规则导入成功")
            else:
                messagebox.showerror("失败", "规则导入失败，请查看日志")
    
    def _on_close(self):
        """窗口关闭处理，确保线程正确终止"""
        with self.lock:
            self.scanning = False
            self.paused = False
        time.sleep(0.5)  # 给线程时间停止
        self.root.destroy()

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AICodeAuditor(root)
        root.mainloop()
    except Exception as e:
        logger.critical(f"应用程序崩溃: {str(e)}\n{traceback.format_exc()}")
        messagebox.showerror("致命错误", f"应用程序崩溃: {str(e)}")
