"""
demo_decorators.py - 装饰器模式函数级保护示例
=============================================

演示如何用装饰器把激活校验嵌入到每个关键函数中，让破解者必须
逐个 patch 才能绕过保护（而不是只 patch 启动校验一次）。

设计要点：
  - 每次调用受保护函数都重新校验激活态
  - 校验前先跑反调试（防止破解者用调试器分析校验逻辑）
  - 校验失败抛异常，不返回默认值（更难绕过）
  - 用 functools.wraps 隐藏装饰器痕迹
  - 校验结果做缓存（30 秒内同一函数不重复校验，平衡性能与安全）

适用场景：核心算法、付费功能、导出/打印、保存等关键路径

运行：
    cd /home/z/my-project/download/license-sdk-python/demos
    python demo_decorators.py
"""

from __future__ import annotations

import functools
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from license_sdk import LicenseVerifier, LicenseConfig


# ---------------------------------------------------------------------------
# 自定义异常
# ---------------------------------------------------------------------------

class LicenseError(Exception):
    """激活态异常基类。"""


class LicenseExpiredError(LicenseError):
    """授权已过期。"""


class LicenseRevokedError(LicenseError):
    """授权已被吊销。"""


class SecurityViolationError(LicenseError):
    """检测到调试器/虚拟机。"""


# ---------------------------------------------------------------------------
# 全局 verifier 单例
# ---------------------------------------------------------------------------

_verifier: LicenseVerifier | None = None


def get_verifier() -> LicenseVerifier:
    global _verifier
    if _verifier is None:
        _verifier = LicenseVerifier(LicenseConfig(
            public_key_b64=os.environ.get(
                "LICENSE_ED25519_PUBKEY_B64",
                LicenseConfig().public_key_b64,
            ),
            keygen_url=os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000"),
            software_version="demo-decorator-1.0.0",
            refuse_in_vm=False,
        ))
    return _verifier


# ---------------------------------------------------------------------------
# 校验缓存（30 秒）
# ---------------------------------------------------------------------------

_check_cache: dict[str, tuple[float, bool]] = {}
_CACHE_TTL = 30.0  # 30 秒


def _cached_check(func_name: str) -> bool:
    """带缓存的校验，避免每次函数调用都跑全套检查。"""
    now = time.time()
    cached = _check_cache.get(func_name)
    if cached and (now - cached[0]) < _CACHE_TTL:
        return cached[1]

    verifier = get_verifier()
    # 1. 反调试预检
    ok, reason = verifier.preflight()
    if not ok:
        _check_cache[func_name] = (now, False)
        raise SecurityViolationError(f"security check failed: {reason}")
    # 2. 激活态校验
    status = verifier.check_status()
    if not status.is_activated:
        _check_cache[func_name] = (now, False)
        if status.is_expired:
            raise LicenseExpiredError(f"license expired: {status.failure_reason}")
        if status.is_revoked:
            raise LicenseRevokedError("license revoked by server")
        raise LicenseError(f"not activated: {status.failure_reason}")
    _check_cache[func_name] = (now, True)
    return True


# ---------------------------------------------------------------------------
# 装饰器
# ---------------------------------------------------------------------------

def requires_license(func):
    """
    装饰器：被装饰的函数在每次调用前都会校验激活态。
    失败则抛出 LicenseError 子类异常。
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        _cached_check(func.__name__)
        return func(*args, **kwargs)
    return wrapper


def requires_license_silent(func):
    """
    装饰器（静默版）：校验失败时不抛异常，而是返回 None。
    适合可选功能（如高级教程、彩蛋等），失败时静默降级。
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            _cached_check(func.__name__)
        except LicenseError:
            return None
        return func(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# 受保护的"软件功能"
# ---------------------------------------------------------------------------

@requires_license
def export_data(data: str, filename: str) -> str:
    """受保护：导出数据到文件。未激活抛 LicenseError。"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(data)
    return f"已导出 {len(data)} 字节到 {filename}"


@requires_license
def generate_report(data: dict) -> str:
    """受保护：生成专业报告。"""
    lines = ["=" * 50, "  专业报告", "=" * 50]
    for k, v in data.items():
        lines.append(f"  {k:<20} : {v}")
    lines.append("=" * 50)
    return "\n".join(lines)


@requires_license
def run_premium_algorithm(n: int) -> int:
    """受保护：付费版才有的高级算法（斐波那契）。"""
    if n < 2:
        return n
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


@requires_license_silent
def get_easter_egg():
    """受保护（静默版）：彩蛋功能。未激活时返回 None 而非抛异常。"""
    return "🎉 你发现了彩蛋!（仅付费用户可见）"


@requires_license
def batch_process(items: list) -> list:
    """受保护：批量处理。"""
    return [f"processed-{i}-{item}" for i, item in enumerate(items)]


# ---------------------------------------------------------------------------
# 也可以保护类的方法
# ---------------------------------------------------------------------------

class DataProcessor:
    """模拟一个数据处理类。"""

    def __init__(self, name: str):
        self.name = name

    @requires_license
    def process(self, data: str) -> str:
        """受保护的实例方法。"""
        return f"[{self.name}] {data.upper()}"

    @requires_license
    def save(self, path: str, data: str) -> str:
        """受保护的实例方法。"""
        with open(path, "w") as f:
            f.write(data)
        return f"saved {len(data)} bytes"


# ---------------------------------------------------------------------------
# 演示主流程
# ---------------------------------------------------------------------------

def try_activate():
    """尝试激活（如果未激活）。"""
    verifier = get_verifier()
    status = verifier.check_status()
    if status.is_activated:
        print(f"✓ 已激活: {status.code_id} ({status.card_type}), 剩余 {status.remaining_days} 天")
        return True
    print(f"✗ 未激活: {status.failure_reason}")
    code = input("  输入激活码（或回车跳过）: ").strip()
    if not code:
        return False
    ok, msg = verifier.activate(code)
    if ok:
        print(f"  ✓ {msg}")
        return True
    print(f"  ✗ {msg}")
    return False


def main():
    print("=" * 60)
    print("  Decorator Demo - 函数级授权保护")
    print("=" * 60)

    if not try_activate():
        print("\n未激活，仅能调用未受保护的函数。")
        print("以下演示调用受保护函数时的行为（会抛 LicenseError）：")

    print("\n--- 调用受保护函数 ---")
    try:
        result = generate_report({"项目": "A", "金额": 100, "时间": "2026-07-24"})
        print("✓ generate_report 成功:")
        print(result)
    except LicenseError as e:
        print(f"✗ generate_report 失败: {e}")

    try:
        result = run_premium_algorithm(10)
        print(f"✓ run_premium_algorithm(10) = {result}")
    except LicenseError as e:
        print(f"✗ run_premium_algorithm 失败: {e}")

    try:
        result = batch_process(["a", "b", "c"])
        print(f"✓ batch_process = {result}")
    except LicenseError as e:
        print(f"✗ batch_process 失败: {e}")

    print("\n--- 调用静默版（失败返回 None） ---")
    egg = get_easter_egg()
    if egg is None:
        print("✗ 彩蛋未返回（未激活）")
    else:
        print(f"✓ 彩蛋: {egg}")

    print("\n--- 调用类方法 ---")
    processor = DataProcessor("Processor-X")
    try:
        result = processor.process("hello world")
        print(f"✓ processor.process = {result}")
    except LicenseError as e:
        print(f"✗ processor.process 失败: {e}")

    print("\n--- 模拟授权过期（修改时间） ---")
    print("  实际场景中，授权过期会在下次校验时被发现。")
    print("  缓存有效期 30 秒，过期后下次调用会重新校验。")

    print("\n" + "=" * 60)
    print("  Demo 完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
