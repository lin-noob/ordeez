import logging
from typing import Optional, Dict, Any
from config.settings import settings
from src.utils.crypto import BTCCrypto
from src.utils.http_client import HTTPClient

logger = logging.getLogger(__name__)


class BTCAuthManager:
    """BTC认证管理器"""

    def __init__(self):
        self.btc_config = settings.get_btc_config()
        self.api_config = settings.get_api_config()

        # 初始化组件
        self.crypto = BTCCrypto(
            network=self.btc_config.get('network', 'testnet'))
        self.http_client = HTTPClient()

        # 配置信息
        self.private_key = self.btc_config.get('private_key')
        self.payment_address = self.btc_config.get('payment_address')
        self.public_key = self.btc_config.get('public_key')
        self.wallet_type = self.btc_config.get('wallet_type', 'unisat')

        # 认证状态
        self.access_token = None
        self.is_authenticated = False

        # 验证配置
        self._validate_config()

    def _validate_config(self):
        """验证配置完整性"""
        required_fields = ['private_key']
        missing_fields = []

        for field in required_fields:
            if not self.btc_config.get(field):
                missing_fields.append(f"btc.{field}")

        if missing_fields:
            raise ValueError(f"缺少必需的配置项: {', '.join(missing_fields)}")

        # 检查可选配置
        if not self.payment_address:
            logger.warning("未配置payment_address，将跳过地址验证")

        if not self.public_key:
            logger.warning("未配置public_key，将尝试从私钥生成")
            # 尝试从私钥生成公钥
            generated_pubkey = self.crypto.get_public_key(self.private_key)
            if generated_pubkey:
                self.public_key = generated_pubkey
                logger.info(f"✅ 从私钥生成公钥: {self.public_key}")
            else:
                logger.warning("无法从私钥生成公钥")

        logger.info("✅ 配置验证通过")

    async def authenticate(self) -> bool:
        """执行完整的认证流程"""
        try:
            logger.info("🚀 开始BTC认证流程...")

            # 步骤1: 验证地址匹配（可选）
            if self.payment_address:
                if not self._verify_address_match():
                    logger.warning("地址验证失败，但继续执行认证流程")
            else:
                logger.info("跳过地址验证（未配置payment_address）")

            # 步骤2: 获取签名消息
            message = await self._get_sign_message()
            if not message:
                logger.error("获取签名消息失败")
                return False

            # 步骤3: 签名消息
            signature = await self._sign_message(message)
            if not signature:
                logger.error("消息签名失败")
                return False

            # 步骤4: 验证签名并获取token
            token = await self._verify_signature(message, signature)
            if not token:
                logger.error("签名验证失败")
                return False

            # 步骤5: 保存认证状态
            self._save_auth_state(token)

            logger.info("🎉 BTC认证成功！")
            return True

        except Exception as e:
            logger.error(f"BTC认证流程失败: {e}")
            return False

    def _verify_address_match(self) -> bool:
        """验证私钥与地址匹配（可选步骤）"""
        try:
            logger.info("验证地址匹配...")

            return self.crypto.verify_address(
                self.private_key,
                self.payment_address
            )

        except Exception as e:
            logger.error(f"地址验证异常: {e}")
            return False

    async def _get_sign_message(self) -> Optional[str]:
        """获取需要签名的消息"""
        try:
            logger.info("获取签名消息...")

            endpoint = self.api_config.get('message_endpoint')
            response = self.http_client.get(endpoint)

            if response and response.get('success'):
                message = response.get('data', {}).get('message')
                if message:
                    logger.info("✅ 签名消息获取成功")
                    logger.debug(f"消息内容: {message}")
                    return message

            logger.error(f"获取签名消息失败: {response}")
            return None

        except Exception as e:
            logger.error(f"获取签名消息异常: {e}")
            return None

    async def _sign_message(self, message: str) -> Optional[str]:
        """签名消息"""
        try:
            logger.info("签名消息...")

            signature = self.crypto.sign_message(self.private_key, message)

            if signature:
                logger.info("✅ 消息签名成功")
                return signature

            return None

        except Exception as e:
            logger.error(f"消息签名异常: {e}")
            return None

    async def _verify_signature(self, message: str, signature: str) -> Optional[str]:
        """验证签名并获取token"""
        try:
            logger.info("验证签名...")

            # IJENj7uBjx9dEzIPxnGOHDPWWBIV+n0pgnekkt7JnqfvB7WPcMz7ak9rQa+V3RVbwt84n4VzVDrEfQrZPgxyGWk=
            # 构建验证参数
            params = {
                'message': message,
                'signature': signature,
                'walletType': self.wallet_type,
                'referrer': ''
            }

            # 添加可选参数
            if self.payment_address:
                params['paymentAddress'] = self.payment_address

            if self.public_key:
                params['publicKey'] = self.public_key

            logger.info(f"验证参数: {params}")

            endpoint = self.api_config.get('verify_endpoint')
            response = self.http_client.post(endpoint, None, json_data=params)

            if response and response.get('success'):
                token = response.get('data', {}).get('token')
                if token:
                    logger.info("✅ 签名验证成功")
                    logger.debug(f"Token: {token[:50]}...")
                    return token

            logger.error(f"签名验证失败: {response}")
            return None

        except Exception as e:
            logger.error(f"签名验证异常: {e}")
            return None

    def _save_auth_state(self, token: str):
        """保存认证状态"""
        self.access_token = token
        self.is_authenticated = True

        # 设置HTTP客户端的认证token
        self.http_client.set_auth_token(token)

        logger.info("✅ 认证状态已保存")

    def get_auth_info(self) -> Dict[str, Any]:
        """获取认证信息"""
        return {
            'is_authenticated': self.is_authenticated,
            'payment_address': self.payment_address,
            'public_key': self.public_key,
            'wallet_type': self.wallet_type,
            'has_token': bool(self.access_token),
            'private_key_format': self.crypto.key_handler.detect_key_format(self.private_key) if self.private_key else None
        }

    def get_authenticated_client(self) -> HTTPClient:
        """获取已认证的HTTP客户端"""
        if not self.is_authenticated:
            raise ValueError("未认证，请先调用authenticate()")
        return self.http_client

    def logout(self):
        """清理认证状态"""
        self.access_token = None
        self.is_authenticated = False
        self.http_client.clear_auth_token()
        logger.info("认证状态已清理")
