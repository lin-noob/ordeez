import json
import os
from pathlib import Path
from typing import Dict, Any


class Settings:
    """配置管理类"""

    def __init__(self, config_file: str = None):
        if config_file is None:
            config_file = Path(__file__).parent / "config.json"

        self.config_file = config_file
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 从环境变量覆盖敏感配置
            self._override_from_env(config)

            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"配置文件未找到: {self.config_file}")
        except json.JSONDecodeError as e:
            raise ValueError(f"配置文件格式错误: {e}")

    def _override_from_env(self, config: Dict[str, Any]):
        """从环境变量覆盖配置"""
        # BTC配置
        if os.getenv('BTC_PRIVATE_KEY'):
            config['btc']['private_key'] = os.getenv('BTC_PRIVATE_KEY')

        if os.getenv('BTC_PAYMENT_ADDRESS'):
            config['btc']['payment_address'] = os.getenv('BTC_PAYMENT_ADDRESS')

        if os.getenv('BTC_PUBLIC_KEY'):
            config['btc']['public_key'] = os.getenv('BTC_PUBLIC_KEY')

        # Twitter配置
        if os.getenv('TWITTER_USERNAME'):
            config['twitter']['username'] = os.getenv('TWITTER_USERNAME')

        if os.getenv('TWITTER_PASSWORD'):
            config['twitter']['password'] = os.getenv('TWITTER_PASSWORD')

        # API配置
        if os.getenv('API_BASE_URL'):
            config['api']['base_url'] = os.getenv('API_BASE_URL')

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值，支持点号分隔的路径"""
        keys = key.split('.')
        value = self._config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def get_btc_config(self) -> Dict[str, Any]:
        """获取BTC配置"""
        return self._config.get('btc', {})

    def get_twitter_config(self) -> Dict[str, Any]:
        """获取Twitter配置"""
        return self._config.get('twitter', {})

    def get_api_config(self) -> Dict[str, Any]:
        """获取API配置"""
        return self._config.get('api', {})

    def get_headers_config(self) -> Dict[str, Any]:
        """获取请求头配置"""
        return self._config.get('headers', {})

    def get_logging_config(self) -> Dict[str, Any]:
        """获取日志配置"""
        return self._config.get('logging', {})


# 全局配置实例
settings = Settings()
