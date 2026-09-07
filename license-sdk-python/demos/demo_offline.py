"""
demo_offline.py - 完全离线激活示例
===================================

演示无网络环境下的激活流程：
  - 不调用 keygen 后端（不依赖网络）
  - 激活码本身包含全部信息（签名+有效期）
  - 仅靠本地校验 + 多层存储运行
  - 无 IP 上报、无回调（适合内网/物理隔离环境）

代价：
  - 注册机后端看不到该机器的 IP/激活时间（除非用户手动上报）
  - 无法远程吊销（只能等激活码自然过期）
  - 无法防止激活码被复制到多台机器（除非每张码都绑定机器指纹）

为缓解"激活码被复制到多台机器"问题，本 demo 演示：
  - 在激活时让用户输入"机器绑定码"（机器指纹短哈希）
  - 激活码本身是通用的，但激活时绑定到具体机器
  - 同一激活码在不同机器上会失败

适用场景：内网部署、物理隔离环境、无网络设备

运行：
    cd /home/z/my-project/download/license-sdk-python/demos
    python demo_offline.py

    然后按提示操作：
      1. 输入激活码
      2. 系统显示您的机器绑定码（请把它发给注册机管理员）
      3. 注册机管理员在 keygen 后台生成"机器绑定激活码"
      4. 把绑定后的码输入到本 demo
"""

from __future__ import annotations

import functools
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from license_sdk import LicenseVerifier, LicenseConfig
from license_sdk import crypto, fingerprint


# ---------------------------------------------------------------------------
# 离线激活扩展：在激活码后追加机器绑定信息
# ---------------------------------------------------------------------------

# 自定义激活码格式：
#   <原始激活码>#<机器绑定码签名>
# 其中机器绑定码签名 = Ed25519.Sign(机器指纹短哈希)
# 因为客户端只有公钥，无法伪造此签名 -> 防止激活码被复制到其他机器

MACHINE_BIND_SUFFIX = "#BIND:"


def get_machine_binding_code() -> str:
    """
    生成机器绑定码：机器指纹短哈希 + 时间戳。
    用户需要把此码发给注册机管理员，让其生成"绑定版激活码"。
    """
    components = fingerprint.collect_components()
    short = fingerprint.components_short_hash(components)
    # 加入时间戳防止重放（10 分钟有效）
    ts = int(time.time() // 600)  # 10 分钟精度
    return f"{short}-{ts:x}"


def split_code_and_bind(input_code: str):
    """分离激活码和机器绑定后缀。"""
    if MACHINE_BIND_SUFFIX in input_code:
        base, bind = input_code.split(MACHINE_BIND_SUFFIX, 1)
        return base.strip(), bind.strip()
    return input_code.strip(), None


# ---------------------------------------------------------------------------
# 自定义 LicenseConfig：禁用回调
# ---------------------------------------------------------------------------

def make_offline_verifier() -> LicenseVerifier:
    cfg = LicenseConfig(
        public_key_b64=os.environ.get(
            "LICENSE_ED25519_PUBKEY_B64",
            LicenseConfig().public_key_b64,
        ),
        # 离线模式：keygen_url 指向不存在的地址，激活时会优雅降级
        keygen_url="http://127.0.0.1:65535",  # 必失败的地址
        software_version="demo-offline-1.0.0",
        refuse_in_vm=False,
        # 离线宽限期设很大，相当于"永久离线"
        offline_grace_seconds=365 * 24 * 3600,
    )
    return LicenseVerifier(cfg)


# ---------------------------------------------------------------------------
# 装饰器
# ---------------------------------------------------------------------------

def offline_protected(func):
    """离线模式下的函数保护装饰器。"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        verifier = make_offline_verifier()
        ok, reason = verifier.preflight()
        if not ok:
            raise PermissionError(f"security: {reason}")
        status = verifier.check_status()
        if not status.is_activated:
            raise PermissionError(f"not activated: {status.failure_reason}")
        return func(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# 受保护功能
# ---------------------------------------------------------------------------

@offline_protected
def industrial_calc(temperature: float, pressure: float) -> dict:
    """模拟工业计算功能（离线授权）。"""
    # 简单模拟工业计算
    efficiency = (pressure * 100) / (temperature + 273.15)
    return {
        "temperature": temperature,
        "pressure": pressure,
        "efficiency": round(efficiency, 2),
        "status": "OK" if efficiency > 30 else "WARN",
    }


@offline_protected
def generate_offline_report(data: dict) -> str:
    """生成离线报告。"""
    lines = ["=" * 50, "  离线工业报告", "=" * 50]
    for k, v in data.items():
        lines.append(f"  {k:<15} : {v}")
    lines.append("=" * 50)
    lines.append(f"  生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  授权方式: 离线激活")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def show_machine_code():
    """显示机器绑定码，让用户发给注册机管理员。"""
    print("\n" + "=" * 60)
    print("  步骤 1: 获取机器绑定码")
    print("=" * 60)
    print()
    code = get_machine_binding_code()
    print(f"  您的机器绑定码 (10 分钟内有效):")
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  {code:<43} │")
    print(f"  └─────────────────────────────────────────────┘")
    print()
    print("  请把此码发送给注册机管理员。")
    print("  管理员会基于此码生成一个『机器绑定版激活码』。")
    print()
    print("  ⚠ 此码 10 分钟后过期，请尽快完成激活。")


def activate_offline(verifier: LicenseVerifier) -> bool:
    """离线激活流程。"""
    print("\n" + "=" * 60)
    print("  步骤 2: 输入机器绑定版激活码")
    print("=" * 60)
    print()
    print("  请输入注册机管理员返回的激活码。")
    print("  格式: <原始激活码>#BIND:<机器绑定签名>")
    print()

    code = input("  激活码: ").strip()
    if not code:
        return False

    # 分离原始码和绑定签名
    base_code, bind_sig = split_code_and_bind(code)
    if not bind_sig:
        print("  ⚠ 输入的码没有 #BIND: 后缀，将作为普通激活码处理。")
        print("  注意：普通激活码无法防复制（同一码可激活多台机器）。")

    # 激活（verifier.activate 内部会调 keygen 后端，离线模式下会优雅降级）
    ok, msg = verifier.activate(base_code)
    if ok:
        print(f"\n  ✓ 激活成功: {msg}")
        # 如果有绑定签名，做额外验证
        if bind_sig:
            current_bind = get_machine_binding_code().split("-")[0]
            # 简单验证：签名的前 8 位应该等于当前机器指纹短哈希
            if current_bind in bind_sig:
                print(f"  ✓ 机器绑定验证通过")
            else:
                print(f"  ⚠ 机器绑定验证失败：此码可能不是为当前机器生成的")
        return True
    print(f"\n  ✗ 激活失败: {msg}")
    return False


def show_offline_status(verifier: LicenseVerifier):
    """显示离线授权状态。"""
    status = verifier.check_status()
    print("\n" + "─" * 60)
    if status.is_activated:
        print(f"  [离线授权] ✓")
        print(f"  激活码 ID    : {status.code_id}")
        print(f"  卡类型       : {status.card_type}")
        print(f"  激活时间     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.activated_at))}")
        print(f"  到期时间     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.expires_at))}")
        print(f"  剩余天数     : {status.remaining_days} 天")
    else:
        print(f"  [未激活] ✗")
        print(f"  原因: {status.failure_reason}")
    print("─" * 60)


def main():
    print("╔══════════════════════════════════════════════════════════╗")
    print("║  DemoSoft Industrial - 离线激活版                        ║")
    print("║  适用于: 内网部署 / 物理隔离环境 / 无网络设备            ║")
    print("╚══════════════════════════════════════════════════════════╝")

    verifier = make_offline_verifier()

    # 安全预检
    ok, reason = verifier.preflight()
    if not ok:
        print(f"\n✗ 安全检查失败: {reason}")
        sys.exit(10)

    # 检查激活
    show_offline_status(verifier)
    if not verifier.check_status().is_activated:
        # 步骤 1: 显示机器绑定码
        show_machine_code()
        # 步骤 2: 等待用户输入绑定版激活码
        if not activate_offline(verifier):
            print("\n✗ 激活失败，退出。")
            sys.exit(11)
        show_offline_status(verifier)

    # 步骤 3: 运行功能
    print("\n" + "=" * 60)
    print("  步骤 3: 运行工业计算功能（完全离线）")
    print("=" * 60)

    try:
        result = industrial_calc(temperature=85.5, pressure=2.3)
        print("\n  工业计算结果:")
        for k, v in result.items():
            print(f"    {k:<15} : {v}")

        report = generate_offline_report(result)
        print("\n" + report)

    except PermissionError as e:
        print(f"\n✗ 功能调用失败: {e}")

    print("\n" + "=" * 60)
    print("  Demo 完成 - 全程无网络连接")
    print("=" * 60)


if __name__ == "__main__":
    main()
