"""LuckMail (mails.luckyous.com) 邮箱 OTP 取码 Provider。

LuckMail 提供两种业务模式：
  - Mode A: 接码（按成功付费，单次使用）
  - Mode B: 购买邮箱（一次性购买，获得 email + token，可长期查询收件箱）

本项目使用 Mode B：购买邮箱后，用 token 通过 OpenAPI 查询收件箱获取 OTP。
这样同一邮箱在注册链路中可能收到多封 OpenAI 邮件时都能读取。

认证方式（OpenAPI）:
  X-API-Key:   {api_key}
  X-Timestamp: {unix_timestamp}
  X-Signature: HMAC-SHA256(api_secret, method + path + timestamp + body)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

LUCKMAIL_BASE_URL = "https://mails.luckyous.com"
LUCKMAIL_OPENAPI_BASE = f"{LUCKMAIL_BASE_URL}/api/v1/openapi"

DEFAULT_PROJECT_CODE = "openai"
DEFAULT_EMAIL_TYPE = "ms_graph"
DEFAULT_DOMAIN = "outlook.com"


# ──────────────────────── OpenAPI 认证 ────────────────────────


def _sign_request(
    api_secret: str,
    method: str,
    path: str,
    timestamp: str,
    body: str = "",
) -> str:
    """生成 HMAC-SHA256 签名。

    method + path + timestamp + body
    """
    base = f"{method.upper()}{path}{timestamp}{body}"
    return hmac.new(
        api_secret.encode("utf-8"),
        base.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _luckmail_headers(api_key: str, api_secret: str, method: str, path: str, body: str = "") -> dict:
    ts = str(int(time.time()))
    sig = _sign_request(api_secret, method, path, ts, body)
    return {
        "X-API-Key": api_key,
        "X-Timestamp": ts,
        "X-Signature": sig,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _request(
    api_key: str,
    api_secret: str,
    method: str,
    path: str,
    *,
    json_body: Optional[dict] = None,
    params: Optional[dict] = None,
    timeout: int = 30,
    proxy: Optional[str] = None,
) -> dict:
    """发起 LuckMail OpenAPI 请求并返回 data 字段。"""
    url = f"{LUCKMAIL_OPENAPI_BASE}{path}"
    body = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False) if json_body else ""
    headers = _luckmail_headers(api_key, api_secret, method, path, body)
    proxies = {"http": proxy, "https": proxy} if proxy else None

    try:
        resp = requests.request(
            method.upper(),
            url,
            headers=headers,
            data=body.encode("utf-8") if body else None,
            params=params,
            timeout=timeout,
            proxies=proxies,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.HTTPError as e:
        try:
            detail = e.response.json()
        except Exception:
            detail = e.response.text[:300]
        raise RuntimeError(f"LuckMail API HTTP {e.response.status_code}: {detail}") from e
    except Exception as e:
        raise RuntimeError(f"LuckMail API 请求失败: {e}") from e

    if not isinstance(data, dict):
        raise RuntimeError(f"LuckMail API 返回异常: {data}")
    if data.get("code") != 0:
        raise RuntimeError(f"LuckMail API 错误: {data.get('message')} (code={data.get('code')})")
    return data.get("data", {})


# ──────────────────────── OTP 抽取 ────────────────────────


def _extract_otp_from_text(text: str) -> Optional[str]:
    """从邮件文本中抽取 6 位 OTP。"""
    import re
    if not text:
        return None
    # 优先语义匹配
    for pat in (
        r"(?:code(?:\s*is)?|verification|one[-\s]*time|verify|kode|verifikasi|代码|验证码|驗證碼)[^\d<>]{0,80}(\d{6})\b",
        r"chatgpt[^\d<>]{0,80}(\d{6})",
        r"openai[^\d<>]{0,80}(\d{6})",
    ):
        for m in re.finditer(pat, text, re.IGNORECASE | re.DOTALL):
            return m.group(1)
    # fallback
    for m in re.finditer(r"\b(\d{6})\b", text):
        return m.group(1)
    return None


# ──────────────────────── 公共 API ────────────────────────


def purchase_emails(
    api_key: str,
    api_secret: str,
    *,
    project_code: str = DEFAULT_PROJECT_CODE,
    email_type: str = DEFAULT_EMAIL_TYPE,
    domain: str = DEFAULT_DOMAIN,
    quantity: int = 1,
    proxy: Optional[str] = None,
) -> list[dict]:
    """批量购买邮箱。返回 [{email_address, token, project, price}, ...]。"""
    if quantity < 1:
        raise ValueError("quantity 必须 >= 1")
    data = _request(
        api_key,
        api_secret,
        "POST",
        "/email/purchase",
        json_body={
            "project_code": project_code,
            "email_type": email_type,
            "domain": domain,
            "quantity": quantity,
        },
        proxy=proxy,
        timeout=60,
    )
    purchases = data.get("purchases") if isinstance(data, dict) else data
    if not isinstance(purchases, list):
        raise RuntimeError(f"LuckMail purchase 返回结构异常: {data}")
    logger.info(f"[luckmail] 购买 {quantity} 个邮箱成功，实际返回 {len(purchases)} 个")
    return purchases


def query_code_by_token(
    api_key: str,
    api_secret: str,
    token: str,
    proxy: Optional[str] = None,
) -> Optional[str]:
    """通过 token 查询最新验证码。"""
    data = _request(
        api_key,
        api_secret,
        "GET",
        f"/email/token/{token}/code",
        proxy=proxy,
        timeout=20,
    )
    if isinstance(data, dict):
        code = data.get("verification_code") or data.get("code")
        if code:
            return str(code).strip()
    return None


def query_mails_by_token(
    api_key: str,
    api_secret: str,
    token: str,
    proxy: Optional[str] = None,
) -> list[dict]:
    """通过 token 查询邮件列表（带 bodies）。"""
    data = _request(
        api_key,
        api_secret,
        "GET",
        f"/email/token/{token}/mails",
        proxy=proxy,
        timeout=20,
    )
    if isinstance(data, dict):
        mails = data.get("mails") or data.get("list") or []
    elif isinstance(data, list):
        mails = data
    else:
        mails = []
    return mails if isinstance(mails, list) else []


# ──────────────────────── MailProvider 适配 ────────────────────────


class LuckMailProvider:
    """适配 auth_flow.run_register 的 LuckMail Provider。

    构造时传入已购买的 email + token；create_mailbox 直接返回该邮箱，
    wait_for_otp 通过 token 查询 LuckMail 收件箱。
    """

    def __init__(
        self,
        api_key: str,
        api_secret: str,
        email: str,
        token: str,
        *,
        proxy: Optional[str] = None,
    ):
        if not api_key or not api_secret:
            raise ValueError("LuckMailProvider 需要 api_key + api_secret")
        if not email or not token:
            raise ValueError("LuckMailProvider 需要 email + token")
        self.api_key = api_key
        self.api_secret = api_secret
        self.email = email
        self.token = token
        self.proxy = proxy
        # 兼容 auth_flow 接口
        self.last_persona = None
        self._outlook_creds = None
        self.outlook_exhausted = False
        self._seen_message_ids: set = set()

    def create_mailbox(self) -> str:
        logger.info(f"[luckmail] 使用已购邮箱: {self.email}")
        return self.email

    def wait_for_otp(
        self,
        email_addr: str,
        timeout: int = 120,
        issued_after: Optional[float] = None,
    ) -> str:
        """轮询 token 等待 OTP。"""
        timeout = max(int(timeout), 60)
        deadline = time.time() + timeout
        threshold = (issued_after - 5) if issued_after else (time.time() - 5)
        logger.info(
            f"[luckmail] 等待 OTP -> {email_addr} (token={self.token[:12]}... timeout={timeout}s)"
        )

        while time.time() < deadline:
            try:
                # 先尝试 /code 端点（最快）
                code = query_code_by_token(
                    self.api_key, self.api_secret, self.token, proxy=self.proxy
                )
                if code:
                    logger.info(f"[luckmail] ✅ OTP={code} (from /code)")
                    return code

                # 兜底：拉邮件列表，按时间过滤后抽 OTP
                mails = query_mails_by_token(
                    self.api_key, self.api_secret, self.token, proxy=self.proxy
                )
                # 按 received_at 倒序
                sorted_mails = sorted(
                    mails,
                    key=lambda m: m.get("received_at") or m.get("created_at") or "",
                    reverse=True,
                )
                for mail in sorted_mails:
                    mid = str(mail.get("message_id") or mail.get("id") or "")
                    if mid in self._seen_message_ids:
                        continue
                    self._seen_message_ids.add(mid)

                    received = mail.get("received_at") or mail.get("created_at")
                    try:
                        mail_ts = time.mktime(time.strptime(received[:19], "%Y-%m-%dT%H:%M:%S")) if received else 0
                    except Exception:
                        mail_ts = 0
                    if mail_ts and mail_ts < threshold:
                        continue

                    body = mail.get("html_body") or mail.get("body") or ""
                    code = _extract_otp_from_text(body)
                    if code:
                        logger.info(
                            f"[luckmail] ✅ OTP={code} from message_id={mid} "
                            f"subject={mail.get('subject','')[:50]}"
                        )
                        return code
            except Exception as e:
                logger.warning(f"[luckmail] poll 异常 (吃掉重试): {e}")
            time.sleep(4)

        raise TimeoutError(f"LuckMail OTP timeout {timeout}s for {email_addr}")


if __name__ == "__main__":
    # 独立调试：python mail_luckmail.py <api_key> <api_secret> [project_code] [quantity]
    import sys
    import logging as _logging
    _logging.basicConfig(level=_logging.INFO, format="%(asctime)s %(message)s")
    if len(sys.argv) < 3:
        print("用法: python mail_luckmail.py <api_key> <api_secret> [project_code] [quantity]")
        sys.exit(2)
    key, secret = sys.argv[1], sys.argv[2]
    proj = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_PROJECT_CODE
    qty = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    try:
        purchases = purchase_emails(key, secret, project_code=proj, quantity=qty)
        for p in purchases:
            print(f"email={p.get('email_address')} token={p.get('token')}")
        if purchases:
            provider = LuckMailProvider(key, secret, purchases[0]["email_address"], purchases[0]["token"])
            print(f"等待 OTP（120s）...")
            print(f"OTP: {provider.wait_for_otp(provider.email, timeout=120)}")
    except Exception as ex:
        print(f"ERR: {ex}")
        sys.exit(1)
