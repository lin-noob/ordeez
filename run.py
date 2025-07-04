#!/usr/bin/env python3
"""
BTC测试网自动化项目启动文件
"""

import sys
import asyncio
from pathlib import Path

# 添加项目根目录和正确的site-packages到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 显式添加包含 bitcoinlib 的 site-packages 目录
site_packages_path = r"C:\Users\Administrator\AppData\Roaming\Python\Python312\site-packages"
if site_packages_path not in sys.path:
    sys.path.append(site_packages_path)

# 验证路径是否添加成功
# print("Updated sys.path:", sys.path)

from src.main import main



if __name__ == "__main__":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    print("🚀 启动BTC测试网自动化程序...")
    asyncio.run(main())
