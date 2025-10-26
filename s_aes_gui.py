"""
S-AES算法GUI界面
提供完整的图形化操作界面，支持多种加密模式
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import sys
import os
from s_aes import SAES, DoubleSAES, TripleSAES, MeetInTheMiddleAttack, SAES_CBC


class SAES_GUI:
    """S-AES算法GUI界面主类"""

    def __init__(self, root):
        self.root = root
        self.root.title("S-AES算法演示系统")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # 设置图标（如果有的话）
        try:
            self.root.iconbitmap("icon.ico")
        except:
            pass

        # 延迟初始化变量（避免Tkinter初始化问题）
        self._init_variables()

        # 创建界面
        self.create_widgets()

        # 设置样式
        self.setup_styles()

    def _init_variables(self):
        """初始化Tkinter变量"""
        try:
            self.current_mode = tk.StringVar(value="basic")
            self.triple_mode = tk.StringVar(value="EDE")
            self.status_var = tk.StringVar(value="就绪")
        except RuntimeError:
            # 如果Tkinter还没有准备好，使用普通变量作为后备
            self.current_mode = "basic"
            self.triple_mode = "EDE"
            self.status_var = "就绪"
            # 标记变量状态
            self._tk_vars_available = False
        else:
            self._tk_vars_available = True

    def _get_var(self, var):
        """获取变量值（兼容普通变量和Tkinter变量）"""
        if hasattr(var, 'get'):
            return var.get()
        else:
            return var

    def _set_var(self, var, value):
        """设置变量值（兼容普通变量和Tkinter变量）"""
        if hasattr(var, 'set'):
            var.set(value)
        else:
            # 对于普通变量，直接修改对应的实例变量
            if var is self.current_mode:
                self.current_mode = value
            elif var is self.triple_mode:
                self.triple_mode = value
            elif var is self.status_var:
                self.status_var = value

    def setup_styles(self):
        """设置界面样式"""
        style = ttk.Style()
        style.configure("TLabel", font=("微软雅黑", 10))
        style.configure("TButton", font=("微软雅黑", 10))
        style.configure("TRadiobutton", font=("微软雅黑", 10))
        style.configure("TCheckbutton", font=("微软雅黑", 10))

    def create_widgets(self):
        """创建所有界面组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 创建菜单栏
        self.create_menu_bar()

        # 标题区域
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = ttk.Label(title_frame, text="S-AES算法演示系统",
                               font=("微软雅黑", 16, "bold"))
        title_label.pack()

        subtitle_label = ttk.Label(title_frame,
                                  text="简化AES算法的完整实现与演示",
                                  font=("微软雅黑", 10))
        subtitle_label.pack()

        # 模式选择区域
        mode_frame = ttk.LabelFrame(main_frame, text="加密模式选择", padding="10")
        mode_frame.pack(fill=tk.X, pady=(0, 10))

        self.create_mode_selection(mode_frame)

        # 输入输出区域
        io_frame = ttk.Frame(main_frame)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.create_input_output_area(io_frame)

        # 控制按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.create_control_buttons(button_frame)

        # 状态栏
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X)

        status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                font=("微软雅黑", 9))
        status_label.pack(side=tk.LEFT)

        # 绑定事件
        self.bind_events()

    def create_menu_bar(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="清除所有", command=self.clear_all,
                             accelerator="Ctrl+L")
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit,
                             accelerator="Ctrl+Q")

        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self.show_about)

        # 绑定快捷键
        self.root.bind('<Control-l>', lambda e: self.clear_all())
        self.root.bind('<Control-q>', lambda e: self.root.quit())

    def create_mode_selection(self, parent):
        """创建模式选择区域"""
        # 如果Tkinter变量不可用，使用按钮代替单选按钮
        if not getattr(self, '_tk_vars_available', True):
            # 使用普通按钮
            self.basic_btn = ttk.Button(parent, text="基本模式 (16位密钥)",
                                       command=lambda: self.set_mode("basic"))
            self.basic_btn.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)

            self.double_btn = ttk.Button(parent, text="双重加密 (32位密钥)",
                                        command=lambda: self.set_mode("double"))
            self.double_btn.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

            self.triple_btn = ttk.Button(parent, text="三重加密 (48位密钥)",
                                        command=lambda: self.set_mode("triple"))
            self.triple_btn.grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)

            self.cbc_btn = ttk.Button(parent, text="CBC模式",
                                     command=lambda: self.set_mode("cbc"))
            self.cbc_btn.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

            self.attack_btn = ttk.Button(parent, text="中间相遇攻击",
                                        command=lambda: self.set_mode("meet_in_middle"))
            self.attack_btn.grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)

            # 三重模式选择
            self.triple_mode_frame = ttk.Frame(parent)
            ttk.Label(self.triple_mode_frame, text="三重模式:").pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(self.triple_mode_frame, text="EDE",
                      command=lambda: self.set_triple_mode("EDE")).pack(side=tk.LEFT, padx=(0, 10))
            ttk.Button(self.triple_mode_frame, text="EEE",
                      command=lambda: self.set_triple_mode("EEE")).pack(side=tk.LEFT)

            self.triple_mode_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
            self.triple_mode_frame.grid_remove()
        else:
            # 使用标准的单选按钮
            ttk.Radiobutton(parent, text="基本模式 (16位密钥)",
                           variable=self.current_mode, value="basic",
                           command=self.on_mode_change).grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)

            ttk.Radiobutton(parent, text="双重加密 (32位密钥)",
                           variable=self.current_mode, value="double",
                           command=self.on_mode_change).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

            ttk.Radiobutton(parent, text="三重加密 (48位密钥)",
                           variable=self.current_mode, value="triple",
                           command=self.on_mode_change).grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)

            ttk.Radiobutton(parent, text="CBC模式",
                           variable=self.current_mode, value="cbc",
                           command=self.on_mode_change).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

            ttk.Radiobutton(parent, text="中间相遇攻击",
                           variable=self.current_mode, value="meet_in_middle",
                           command=self.on_mode_change).grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)

            # 三重模式选择
            self.triple_mode_frame = ttk.Frame(parent)
            ttk.Label(self.triple_mode_frame, text="三重模式:").pack(side=tk.LEFT, padx=(0, 5))
            ttk.Radiobutton(self.triple_mode_frame, text="EDE",
                           variable=self.triple_mode, value="EDE").pack(side=tk.LEFT, padx=(0, 10))
            ttk.Radiobutton(self.triple_mode_frame, text="EEE",
                           variable=self.triple_mode, value="EEE").pack(side=tk.LEFT)

            self.triple_mode_frame.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
            self.triple_mode_frame.grid_remove()

    def create_input_output_area(self, parent):
        """创建输入输出区域"""
        # 左侧输入区域
        input_frame = ttk.LabelFrame(parent, text="输入参数", padding="10")
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        self.create_input_area(input_frame)

        # 右侧输出区域
        output_frame = ttk.LabelFrame(parent, text="结果显示", padding="10")
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.create_output_area(output_frame)

    def create_input_area(self, parent):
        """创建输入区域"""
        # 明文输入
        ttk.Label(parent, text="明文 (16进制或ASCII):").pack(anchor=tk.W, pady=(0, 5))
        self.plaintext_entry = ttk.Entry(parent, font=("Consolas", 10))
        self.plaintext_entry.pack(fill=tk.X, pady=(0, 10))

        # 密文输入
        ttk.Label(parent, text="密文 (16进制):").pack(anchor=tk.W, pady=(0, 5))
        self.ciphertext_entry = ttk.Entry(parent, font=("Consolas", 10))
        self.ciphertext_entry.pack(fill=tk.X, pady=(0, 10))

        # 密钥输入区域
        self.create_key_input_area(parent)

    def create_key_input_area(self, parent):
        """创建密钥输入区域"""
        key_frame = ttk.LabelFrame(parent, text="密钥设置", padding="5")
        key_frame.pack(fill=tk.X, pady=(0, 10))

        # 密钥1（所有模式都需要）
        ttk.Label(key_frame, text="密钥1 (16进制):").pack(anchor=tk.W, pady=(0, 2))
        self.key1_entry = ttk.Entry(key_frame, font=("Consolas", 10))
        self.key1_entry.pack(fill=tk.X, pady=(0, 5))
        self.key1_entry.insert(0, "0123")  # 默认值

        # 密钥2（双重、三重、CBC、攻击模式需要）
        self.key2_label = ttk.Label(key_frame, text="密钥2 (16进制):")
        self.key2_entry = ttk.Entry(key_frame, font=("Consolas", 10))

        # 密钥3（三重模式需要）
        self.key3_label = ttk.Label(key_frame, text="密钥3 (16进制):")
        self.key3_entry = ttk.Entry(key_frame, font=("Consolas", 10))

        # IV输入（CBC模式需要）
        self.iv_label = ttk.Label(key_frame, text="初始向量 (16进制):")
        self.iv_entry = ttk.Entry(key_frame, font=("Consolas", 10))

        # 默认隐藏其他密钥输入
        self.key2_label.pack_forget()
        self.key2_entry.pack_forget()
        self.key3_label.pack_forget()
        self.key3_entry.pack_forget()
        self.iv_label.pack_forget()
        self.iv_entry.pack_forget()

    def create_output_area(self, parent):
        """创建输出区域"""
        # 结果显示文本框
        self.result_text = scrolledtext.ScrolledText(parent, height=15,
                                                   font=("Consolas", 10),
                                                   wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # 设置只读
        self.result_text.config(state=tk.DISABLED)

    def create_control_buttons(self, parent):
        """创建控制按钮"""
        # 左侧按钮组
        left_buttons = ttk.Frame(parent)
        left_buttons.pack(side=tk.LEFT)

        ttk.Button(left_buttons, text="加密", command=self.encrypt,
                  style="TButton").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(left_buttons, text="解密", command=self.decrypt,
                  style="TButton").pack(side=tk.LEFT, padx=(0, 5))

        # 右侧按钮组
        right_buttons = ttk.Frame(parent)
        right_buttons.pack(side=tk.RIGHT)

        ttk.Button(right_buttons, text="清除", command=self.clear_all,
                  style="TButton").pack(side=tk.RIGHT, padx=(0, 5))
        ttk.Button(right_buttons, text="运行测试", command=self.run_tests,
                  style="TButton").pack(side=tk.RIGHT)

    def bind_events(self):
        """绑定事件"""
        # 模式切换事件已在创建时绑定
        pass

    def on_mode_change(self):
        """模式切换处理"""
        mode = self._get_var(self.current_mode)

        # 隐藏所有额外密钥输入
        self.key2_label.pack_forget()
        self.key2_entry.pack_forget()
        self.key3_label.pack_forget()
        self.key3_entry.pack_forget()
        self.iv_label.pack_forget()
        self.iv_entry.pack_forget()
        self.triple_mode_frame.grid_remove()

        # 根据模式显示相应输入
        if mode == "double":
            self.key2_label.pack(anchor=tk.W, pady=(0, 2))
            self.key2_entry.pack(fill=tk.X, pady=(0, 5))
            self.key2_entry.delete(0, tk.END)
            self.key2_entry.insert(0, "4567")
        elif mode == "triple":
            self.key2_label.pack(anchor=tk.W, pady=(0, 2))
            self.key2_entry.pack(fill=tk.X, pady=(0, 5))
            self.key2_entry.delete(0, tk.END)
            self.key2_entry.insert(0, "4567")
            self.key3_label.pack(anchor=tk.W, pady=(0, 2))
            self.key3_entry.pack(fill=tk.X, pady=(0, 5))
            self.key3_entry.delete(0, tk.END)
            self.key3_entry.insert(0, "89AB")
            self.triple_mode_frame.grid()
        elif mode == "cbc":
            self.iv_label.pack(anchor=tk.W, pady=(0, 2))
            self.iv_entry.pack(fill=tk.X, pady=(0, 5))
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, "0000")
        elif mode == "meet_in_middle":
            self.key2_label.pack(anchor=tk.W, pady=(0, 2))
            self.key2_entry.pack(fill=tk.X, pady=(0, 5))
            self.key2_entry.delete(0, tk.END)
            self.key2_entry.insert(0, "4567")

        self._set_var(self.status_var, f"切换到{mode}模式")

    def set_mode(self, mode):
        """设置模式（用于按钮模式）"""
        self.current_mode = mode
        self.on_mode_change()

    def set_triple_mode(self, mode):
        """设置三重模式"""
        self.triple_mode = mode
        # 可以在这里添加视觉反馈，比如改变按钮状态

    def get_plaintext_hex(self):
        """获取明文并转换为16进制"""
        text = self.plaintext_entry.get().strip()
        if not text:
            return ""

        # 检查是否为纯16进制
        try:
            int(text, 16)
            # 如果是纯16进制，直接返回
            return text.upper()
        except ValueError:
            # 如果不是纯16进制，当作ASCII字符串处理
            try:
                hex_str = text.encode('utf-8').hex().upper()
                self.log_message(f"ASCII输入已转换为16进制: {text} -> {hex_str}")
                return hex_str
            except Exception as e:
                raise ValueError(f"无效的输入格式: {e}")

    def log_message(self, message):
        """添加日志消息到结果显示框"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)

    def clear_result(self):
        """清除结果显示框"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)

    def encrypt(self):
        """执行加密操作"""
        try:
            self._set_var(self.status_var, "正在加密...")
            self.clear_result()

            mode = self._get_var(self.current_mode)

            if mode == "basic":
                self.encrypt_basic()
            elif mode == "double":
                self.encrypt_double()
            elif mode == "triple":
                self.encrypt_triple()
            elif mode == "cbc":
                self.encrypt_cbc()
            elif mode == "meet_in_middle":
                self.attack_meet_in_middle()

            self._set_var(self.status_var, "加密完成")

        except Exception as e:
            self.log_message(f"❌ 加密失败: {str(e)}")
            self._set_var(self.status_var, "加密失败")
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def decrypt(self):
        """执行解密操作"""
        try:
            self._set_var(self.status_var, "正在解密...")
            self.clear_result()

            mode = self._get_var(self.current_mode)

            if mode == "basic":
                self.decrypt_basic()
            elif mode == "double":
                self.decrypt_double()
            elif mode == "triple":
                self.decrypt_triple()
            elif mode == "cbc":
                self.decrypt_cbc()

            self._set_var(self.status_var, "解密完成")

        except Exception as e:
            self.log_message(f"❌ 解密失败: {str(e)}")
            self._set_var(self.status_var, "解密失败")
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def encrypt_basic(self):
        """基本模式加密"""
        plaintext_hex = self.get_plaintext_hex()
        key1 = self.key1_entry.get().strip().upper()

        if not plaintext_hex or not key1:
            raise ValueError("请输入明文和密钥")

        if len(plaintext_hex) != 4:
            raise ValueError("基本模式下明文必须是4位16进制数（16位）")

        if len(key1) != 4:
            raise ValueError("基本模式下密钥必须是4位16进制数（16位）")

        saes = SAES(key1)
        ciphertext = saes.encrypt(plaintext_hex)

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, ciphertext)

        self.log_message("🔐 基本模式加密结果:")
        self.log_message(f"  明文: {plaintext_hex}")
        self.log_message(f"  密钥: {key1}")
        self.log_message(f"  密文: {ciphertext}")

    def decrypt_basic(self):
        """基本模式解密"""
        ciphertext = self.ciphertext_entry.get().strip().upper()
        key1 = self.key1_entry.get().strip().upper()

        if not ciphertext or not key1:
            raise ValueError("请输入密文和密钥")

        if len(ciphertext) != 4:
            raise ValueError("基本模式下密文必须是4位16进制数（16位）")

        if len(key1) != 4:
            raise ValueError("基本模式下密钥必须是4位16进制数（16位）")

        saes = SAES(key1)
        plaintext = saes.decrypt(ciphertext)

        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        self.log_message("🔓 基本模式解密结果:")
        self.log_message(f"  密文: {ciphertext}")
        self.log_message(f"  密钥: {key1}")
        self.log_message(f"  明文: {plaintext}")

    def encrypt_double(self):
        """双重加密"""
        plaintext_hex = self.get_plaintext_hex()
        key1 = self.key1_entry.get().strip().upper()
        key2 = self.key2_entry.get().strip().upper()

        if not plaintext_hex or not key1 or not key2:
            raise ValueError("请输入明文和两个密钥")

        if len(plaintext_hex) != 4:
            raise ValueError("双重加密模式下明文必须是4位16进制数（16位）")

        if len(key1) != 4 or len(key2) != 4:
            raise ValueError("双重加密模式下密钥必须都是4位16进制数（16位）")

        double_saes = DoubleSAES(key1, key2)
        ciphertext = double_saes.encrypt(plaintext_hex)

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, ciphertext)

        self.log_message("🔐 双重加密结果:")
        self.log_message(f"  明文: {plaintext_hex}")
        self.log_message(f"  密钥1: {key1}")
        self.log_message(f"  密钥2: {key2}")
        self.log_message(f"  密文: {ciphertext}")

    def decrypt_double(self):
        """双重解密"""
        ciphertext = self.ciphertext_entry.get().strip().upper()
        key1 = self.key1_entry.get().strip().upper()
        key2 = self.key2_entry.get().strip().upper()

        if not ciphertext or not key1 or not key2:
            raise ValueError("请输入密文和两个密钥")

        if len(ciphertext) != 4:
            raise ValueError("双重解密模式下密文必须是4位16进制数（16位）")

        if len(key1) != 4 or len(key2) != 4:
            raise ValueError("双重解密模式下密钥必须都是4位16进制数（16位）")

        double_saes = DoubleSAES(key1, key2)
        plaintext = double_saes.decrypt(ciphertext)

        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        self.log_message("🔓 双重解密结果:")
        self.log_message(f"  密文: {ciphertext}")
        self.log_message(f"  密钥1: {key1}")
        self.log_message(f"  密钥2: {key2}")
        self.log_message(f"  明文: {plaintext}")

    def encrypt_triple(self):
        """三重加密"""
        plaintext_hex = self.get_plaintext_hex()
        key1 = self.key1_entry.get().strip().upper()
        key2 = self.key2_entry.get().strip().upper()
        key3 = self.key3_entry.get().strip().upper()
        mode = self._get_var(self.triple_mode)

        if not plaintext_hex or not key1 or not key2 or not key3:
            raise ValueError("请输入明文和三个密钥")

        if len(plaintext_hex) != 4:
            raise ValueError("三重加密模式下明文必须是4位16进制数（16位）")

        if len(key1) != 4 or len(key2) != 4 or len(key3) != 4:
            raise ValueError("三重加密模式下密钥必须都是4位16进制数（16位）")

        triple_saes = TripleSAES(key1, key2, key3, mode)
        ciphertext = triple_saes.encrypt(plaintext_hex)

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, ciphertext)

        self.log_message(f"🔐 三重加密结果 ({mode}模式):")
        self.log_message(f"  明文: {plaintext_hex}")
        self.log_message(f"  密钥1: {key1}")
        self.log_message(f"  密钥2: {key2}")
        self.log_message(f"  密钥3: {key3}")
        self.log_message(f"  密文: {ciphertext}")

    def decrypt_triple(self):
        """三重解密"""
        ciphertext = self.ciphertext_entry.get().strip().upper()
        key1 = self.key1_entry.get().strip().upper()
        key2 = self.key2_entry.get().strip().upper()
        key3 = self.key3_entry.get().strip().upper()
        mode = self._get_var(self.triple_mode)

        if not ciphertext or not key1 or not key2 or not key3:
            raise ValueError("请输入密文和三个密钥")

        if len(ciphertext) != 4:
            raise ValueError("三重解密模式下密文必须是4位16进制数（16位）")

        if len(key1) != 4 or len(key2) != 4 or len(key3) != 4:
            raise ValueError("三重解密模式下密钥必须都是4位16进制数（16位）")

        triple_saes = TripleSAES(key1, key2, key3, mode)
        plaintext = triple_saes.decrypt(ciphertext)

        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        self.log_message(f"🔓 三重解密结果 ({mode}模式):")
        self.log_message(f"  密文: {ciphertext}")
        self.log_message(f"  密钥1: {key1}")
        self.log_message(f"  密钥2: {key2}")
        self.log_message(f"  密钥3: {key3}")
        self.log_message(f"  明文: {plaintext}")

    def encrypt_cbc(self):
        """CBC模式加密"""
        plaintext_hex = self.get_plaintext_hex()
        key1 = self.key1_entry.get().strip().upper()
        iv = self.iv_entry.get().strip().upper()

        if not plaintext_hex or not key1:
            raise ValueError("请输入明文和密钥")

        if not iv:
            iv = None  # 使用随机IV

        if len(key1) != 4:
            raise ValueError("CBC模式下密钥必须是4位16进制数（16位）")

        if iv and len(iv) != 4:
            raise ValueError("CBC模式下初始向量必须是4位16进制数（16位）")

        cbc_saes = SAES_CBC(key1, iv)
        ciphertext = cbc_saes.encrypt(plaintext_hex)

        self.ciphertext_entry.delete(0, tk.END)
        self.ciphertext_entry.insert(0, ciphertext)

        self.log_message("🔐 CBC模式加密结果:")
        self.log_message(f"  明文: {plaintext_hex}")
        self.log_message(f"  密钥: {key1}")
        self.log_message(f"  初始向量: {cbc_saes.get_iv_hex()}")
        self.log_message(f"  密文: {ciphertext}")

    def decrypt_cbc(self):
        """CBC模式解密"""
        ciphertext = self.ciphertext_entry.get().strip().upper()
        key1 = self.key1_entry.get().strip().upper()
        iv = self.iv_entry.get().strip().upper()

        if not ciphertext or not key1:
            raise ValueError("请输入密文和密钥")

        if not iv:
            raise ValueError("CBC模式解密需要指定初始向量")

        if len(key1) != 4:
            raise ValueError("CBC模式下密钥必须是4位16进制数（16位）")

        if len(iv) != 4:
            raise ValueError("CBC模式下初始向量必须是4位16进制数（16位）")

        cbc_saes = SAES_CBC(key1, iv)
        plaintext = cbc_saes.decrypt(ciphertext)

        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        self.log_message("🔓 CBC模式解密结果:")
        self.log_message(f"  密文: {ciphertext}")
        self.log_message(f"  密钥: {key1}")
        self.log_message(f"  初始向量: {iv}")
        self.log_message(f"  明文: {plaintext}")

    def attack_meet_in_middle(self):
        """中间相遇攻击"""
        plaintext = self.plaintext_entry.get().strip().upper()
        ciphertext = self.ciphertext_entry.get().strip().upper()

        if not plaintext or not ciphertext:
            raise ValueError("请输入明文和密文对")

        if len(plaintext) != 4 or len(ciphertext) != 4:
            raise ValueError("明文和密文都必须是4位16进制数（16位）")

        attack = MeetInTheMiddleAttack()
        attack.add_pair(plaintext, ciphertext)

        self.log_message("🎯 开始中间相遇攻击...")
        self.log_message(f"  明文: {plaintext}")
        self.log_message(f"  密文: {ciphertext}")
        self.log_message("  正在搜索密钥对...")

        # 执行攻击
        key1, key2 = attack.attack

        if key1 and key2:
            self.log_message("✅ 找到密钥对！")
            self.log_message(f"  密钥1: {key1}")
            self.log_message(f"  密钥2: {key2}")

            # 验证密钥
            if attack.verify_key(key1, key2):
                self.log_message("✓ 密钥验证通过")
                # 更新输入框
                self.key1_entry.delete(0, tk.END)
                self.key1_entry.insert(0, key1)
                self.key2_entry.delete(0, tk.END)
                self.key2_entry.insert(0, key2)
            else:
                self.log_message("✗ 密钥验证失败")
        else:
            self.log_message("❌ 未找到有效密钥对")

    def clear_all(self):
        """清除所有输入和输出"""
        self.plaintext_entry.delete(0, tk.END)
        self.ciphertext_entry.delete(0, tk.END)
        self.key1_entry.delete(0, tk.END)
        self.key1_entry.insert(0, "0123")
        self.key2_entry.delete(0, tk.END)
        self.key3_entry.delete(0, tk.END)
        self.iv_entry.delete(0, tk.END)
        self.clear_result()
        self._set_var(self.status_var, "已清除所有内容")

    def run_tests(self):
        """运行测试"""
        try:
            self._set_var(self.status_var, "正在运行测试...")

            # 创建测试窗口
            test_window = tk.Toplevel(self.root)
            test_window.title("S-AES算法测试结果")
            test_window.geometry("800x600")

            # 创建滚动文本框
            text_frame = ttk.Frame(test_window, padding="10")
            text_frame.pack(fill=tk.BOTH, expand=True)

            test_text = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10))
            test_text.pack(fill=tk.BOTH, expand=True)

            # 导入并运行测试
            from final_test import S_AES_Final_Test

            # 重定向输出到文本框
            import io
            from contextlib import redirect_stdout

            output_buffer = io.StringIO()

            with redirect_stdout(output_buffer):
                tester = S_AES_Final_Test()
                tester.run_all_tests()

            # 显示结果
            test_text.insert(tk.END, output_buffer.getvalue())
            test_text.config(state=tk.DISABLED)

            self._set_var(self.status_var, "测试完成")

        except Exception as e:
            messagebox.showerror("错误", f"运行测试失败: {str(e)}")
            self._set_var(self.status_var, "测试失败")

    def show_about(self):
        """显示关于对话框"""
        about_text = """S-AES算法演示系统

功能特性:
• 基本S-AES加密解密
• 双重加密/解密
• 三重加密/解密 (EDE/EEE模式)
• CBC工作模式
• 中间相遇攻击演示
• ASCII字符串自动转换
• 完整测试套件

技术实现:
• 基于Python Tkinter
• 完全实现S-AES算法
• 支持16位分组和密钥

© 2025 信息安全课程设计"""

        messagebox.showinfo("关于", about_text)


def main():
    """主函数"""
    root = tk.Tk()
    app = SAES_GUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
