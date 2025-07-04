import logging
import asyncio
import sys
from config.settings import settings
from src.auth.btc_auth import BTCAuthManager
from src.auth.twitter_auth import TwitterAuthManager

# 配置日志


def setup_logging():
    """设置日志配置"""
    log_config = settings.get_logging_config()

    logging.basicConfig(
        level=getattr(logging, log_config.get('level', 'INFO')),
        format=log_config.get('format'),
        handlers=[
            logging.StreamHandler(stream=sys.stdout),
            logging.FileHandler(log_config.get(
                'file', 'btc_automation.log'), encoding='utf-8')
        ]
    )


logger = logging.getLogger(__name__)


class BTCAuthenticatedService:
    """需要认证的BTC服务"""

    def __init__(self, auth_manager: BTCAuthManager):
        self.auth_manager = auth_manager

    async def get_user_profile(self):
        """获取用户资料"""
        if not self.auth_manager.is_authenticated():
            logger.error("未认证，无法获取用户资料")
            return None

        # 模拟API调用
        logger.info("正在获取用户资料...")
        await asyncio.sleep(1)
        return {"username": "test_user", "email": "test@example.com"}

    async def get_balance(self):
        """获取余额"""
        if not self.auth_manager.is_authenticated():
            logger.error("未认证，无法获取余额")
            return None

        # 模拟API调用
        logger.info("正在获取余额...")
        await asyncio.sleep(1)
        return {"balance": 100}


class BTCAutomation:
    """BTC自动化主类"""

    def __init__(self):
        self.auth_manager = BTCAuthManager()
        self.service = BTCAuthenticatedService(self.auth_manager)
        self.twitter_auth_manager = None

    async def run(self) -> bool:
        """运行完整的自动化流程"""
        try:
            logger.info("🚀 开始BTC自动化流程...")

            # 步骤1: BTC认证
            logger.info("步骤 1: BTC认证...")
            if not await self.auth_manager.authenticate():
                logger.error("BTC认证失败")
                return False

            # 步骤2: Twitter认证
            logger.info("步骤 2: Twitter认证...")
            if not await self._authenticate_twitter():
                logger.warning("Twitter认证失败，但继续执行流程")
                # 不返回False，继续执行

            # 步骤3: 执行业务逻辑
            logger.info("步骤 3: 执行业务逻辑...")
            await self._execute_business_logic()

            logger.info("🎉 BTC自动化完成！")
            return True

        except Exception as e:
            logger.error(f"自动化流程失败: {e}")
            return False
        finally:
            # 清理资源
            self.auth_manager.logout()

    async def _authenticate_twitter(self) -> bool:
        """Twitter认证流程"""
        try:
            # 获取BTC地址
            btc_address = self.auth_manager.payment_address
            if not btc_address:
                logger.error("未找到BTC地址，无法进行Twitter认证")
                return False

            # 初始化Twitter认证管理器
            self.twitter_auth_manager = TwitterAuthManager(btc_address)

            # 自动完成Twitter认证流程
            logger.info("开始自动Twitter认证流程...")
            if await self.twitter_auth_manager.authenticate_twitter():
                logger.info("✅ Twitter认证成功")
                return True
            else:
                logger.error("❌ Twitter认证失败")
                return False

        except Exception as e:
            logger.error(f"Twitter认证流程异常: {e}")
            return False

    async def _execute_business_logic(self):
        """执行业务逻辑"""
        try:
            # 获取用户信息
            auth_info = self.auth_manager.get_auth_info()
            logger.info(f"BTC认证信息: {auth_info}")

            # 获取Twitter认证信息
            if self.twitter_auth_manager:
                twitter_auth_info = self.twitter_auth_manager.get_auth_info()
                logger.info(f"Twitter认证信息: {twitter_auth_info}")

            # 执行其他业务操作
            # profile = await self.service.get_user_profile()
            # balance = await self.service.get_balance()

            logger.info("✅ 业务逻辑执行完成")

        except Exception as e:
            logger.error(f"业务逻辑执行失败: {e}")


async def main():
    """主函数"""
    setup_logging()

    try:
        automation = BTCAutomation()
        success = await automation.run()

        if success:
            logger.info("🎉 程序执行成功")
        else:
            logger.error("❌ 程序执行失败")

    except Exception as e:
        logger.error(f"程序异常: {e}")

if __name__ == "__main__":
    asyncio.run(main())
