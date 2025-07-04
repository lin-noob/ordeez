import requests
import time
import logging
from typing import Dict, Any, Optional
from config.settings import settings

logger = logging.getLogger(__name__)


class HTTPClient:
    """HTTP客户端类"""

    def __init__(self):
        self.session = requests.Session()
        self.api_config = settings.get_api_config()
        self.headers_config = settings.get_headers_config()

        # 设置基础请求头
        self.session.headers.update({
            'User-Agent': self.headers_config.get('user_agent'),
            'Accept': self.headers_config.get('accept'),
            'Accept-Language': self.headers_config.get('accept_language'),
            'Accept-Encoding': self.headers_config.get('accept_encoding'),
            'Connection': self.headers_config.get('connection'),
            'Sec-Fetch-Dest': self.headers_config.get('sec_fetch_dest'),
            'Sec-Fetch-Mode': self.headers_config.get('sec_fetch_mode'),
            'Sec-Fetch-Site': self.headers_config.get('sec_fetch_site')
        })

        self.base_url = self.api_config.get('base_url')
        self.timeout = self.api_config.get('timeout', 30)
        self.retry_attempts = self.api_config.get('retry_attempts', 3)
        self.retry_delay = self.api_config.get('retry_delay', 2)

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        """发送HTTP请求，包含重试机制"""
        url = f"{self.base_url}{endpoint}"

        for attempt in range(self.retry_attempts):
            try:
                logger.info(
                    f"发送 {method} 请求到 {url} (尝试 {attempt + 1}/{self.retry_attempts})")

                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    **kwargs
                )

                logger.info(f"响应状态码: {response.status_code}")

                # 检查响应状态
                if response.status_code == 200:
                    return response
                elif response.status_code == 429:
                    # 处理限流
                    retry_after = int(response.headers.get(
                        'Retry-After', self.retry_delay))
                    logger.warning(f"遇到限流，等待 {retry_after} 秒...")
                    time.sleep(retry_after)
                    continue
                else:
                    logger.warning(
                        f"请求失败: {response.status_code} - {response.text}")

            except requests.exceptions.RequestException as e:
                logger.error(f"请求异常 (尝试 {attempt + 1}): {e}")

                if attempt < self.retry_attempts - 1:
                    wait_time = self.retry_delay * (2 ** attempt)  # 指数退避
                    logger.info(f"等待 {wait_time} 秒后重试...")
                    time.sleep(wait_time)

        logger.error(f"所有请求尝试都失败了")
        return None

    def get(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """发送GET请求"""
        response = self._make_request('GET', endpoint, params=params)

        if response:
            try:
                return response.json()
            except ValueError as e:
                logger.error(f"响应JSON解析失败: {e}")
                logger.error(f"原始响应: {response.text}")

        return None

    def post(self, endpoint: str, data: Dict[str, Any] = None, json_data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """发送POST请求"""
        kwargs = {}
        if data:
            kwargs['data'] = data
        if json_data:
            kwargs['json'] = json_data

        response = self._make_request('POST', endpoint, **kwargs)

        if response:
            try:
                return response.json()
            except ValueError as e:
                logger.error(f"响应JSON解析失败: {e}")
                logger.error(f"原始响应: {response.text}")

        return None

    def set_auth_token(self, token: str):
        """设置认证token"""
        self.session.headers.update({
            'Authorization': f'Bearer {token}'
        })
        logger.info("✅ 认证token已设置")

    def get_session(self) -> requests.Session:
        """获取session对象"""
        return self.session

    def clear_auth_token(self):
        """清除认证token"""
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
        logger.info("✅ 认证token已清除")
