"""
S-AES算法GUI界面启动脚本
启动图形化演示界面
"""

import sys
import os

def main():
    """主函数"""
    print("🚀 启动S-AES算法GUI界面")
    print("=" * 40)

    # 检查必要文件是否存在
    required_files = [
        "s_aes_gui.py",
        "s_aes.py"
    ]

    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)

    if missing_files:
        print("❌ 缺少必要文件:")
        for file in missing_files:
            print(f"  • {file}")
        print("\n请确保所有文件都在当前目录中。")
        sys.exit(1)

    print("✅ 必要文件检查通过")

    # 检查Python版本
    if sys.version_info < (3, 6):
        print("❌ 需要Python 3.6或更高版本")
        print(f"当前版本: {sys.version}")
        sys.exit(1)

    print("✅ Python版本检查通过")
    print()

    try:
        print("🎨 正在启动GUI界面...")
        print("提示: 如果界面没有显示，请检查是否有图形界面支持")
        print()

        # 导入并启动GUI
        from s_aes_gui import main as gui_main
        gui_main()

    except ImportError as e:
        print(f"❌ 导入错误: {e}")
        print("请确保已安装所有依赖包。")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n👋 用户中断")
        sys.exit(0)

    except Exception as e:
        print(f"❌ 启动失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
