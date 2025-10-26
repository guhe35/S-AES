"""
S-AES算法最终测试运行脚本
一键执行基于5关要求的完整测试
"""

import sys
import os

def main():
    """主函数"""
    print("🔬 S-AES算法最终测试执行器")
    print("=" * 50)
    print("基于课程5关测试要求，全面验证S-AES算法实现")
    print()

    # 检查必要文件是否存在
    required_files = [
        "s_aes.py",
        "final_test.py",
        "README.md"
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
    print()

    # 导入并运行测试
    try:
        print("🚀 开始执行最终测试...")
        print()

        from final_test import S_AES_Final_Test

        tester = S_AES_Final_Test()
        tester.run_all_tests()

        print()
        print("=" * 50)
        print("🎉 测试执行完成！")
        print()
        print("📖 相关文档:")
        print("  • final_test.py     - 测试套件源码")
        print("  • README.md         - 完整项目文档和测试指南")
        print("  • s_aes.py         - S-AES算法实现")
        print()
        print("💡 如需GUI测试，请运行: python run_gui.py")

    except ImportError as e:
        print(f"❌ 导入错误: {e}")
        print("请确保Python路径正确且所有依赖已安装。")
        sys.exit(1)

    except Exception as e:
        print(f"❌ 测试执行失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
