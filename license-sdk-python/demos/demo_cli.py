"""
demo_cli.py - 命令行软件激活示例
=================================

最简单的集成示例：模拟一个命令行工具，启动时检查激活状态，
未激活则提示用户输入激活码。

适用场景：脚本工具、CLI 工具、批处理程序

运行：
    cd /home/z/my-project/download/license-sdk-python/demos
    python demo_cli.py

环境变量（可选）：
    LICENSE_KEYGEN_URL=http://localhost:3000
    LICENSE_ED25519_PUBKEY_B64=...
"""

from __future__ import annotations

import os
import sys
import time

# 让 demo 能找到父目录的 license_sdk 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from license_sdk import LicenseVerifier, LicenseConfig


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║  DemoSoft CLI v1.0 - 命令行工具示例                          ║
║  Protected by License SDK (Ed25519 + Anti-Debug + Anti-VM)   ║
╚══════════════════════════════════════════════════════════════╝
"""


def build_verifier() -> LicenseVerifier:
    """构造 LicenseVerifier，从环境变量读取配置。"""
    return LicenseVerifier(LicenseConfig(
        public_key_b64=os.environ.get(
            "LICENSE_ED25519_PUBKEY_B64",
            LicenseConfig().public_key_b64,  # 用 SDK 内置的默认公钥
        ),
        keygen_url=os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000"),
        software_version="demo-cli-1.0.0",
        refuse_in_vm=False,  # 生产改 True
    ))


def prompt_activation(verifier: LicenseVerifier) -> bool:
    """提示用户输入激活码，最多 3 次机会。"""
    print("\n" + "=" * 60)
    print("  软件未激活，请输入激活码")
    print("=" * 60)
    print("格式示例: XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-...")
    print()

    for attempt in range(1, 4):
        try:
            code = input(f"[尝试 {attempt}/3] 激活码: ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        if not code:
            continue

        ok, msg = verifier.activate(code)
        if ok:
            print(f"\n✓ 激活成功: {msg}")
            return True
        else:
            print(f"✗ 激活失败: {msg}\n")
    return False


def show_status(status):
    """展示当前激活状态。"""
    print("\n" + "─" * 60)
    print("  授权信息")
    print("─" * 60)
    print(f"  激活码 ID    : {status.code_id}")
    print(f"  卡类型       : {status.card_type}")
    print(f"  激活时间     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.activated_at))}")
    print(f"  到期时间     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(status.expires_at))}")
    print(f"  剩余天数     : {status.remaining_days} 天")
    print("─" * 60)


def run_main_work():
    """模拟软件的主工作循环。"""
    print("\n" + "=" * 60)
    print("  软件正常运行中。输入命令或 'exit' 退出。")
    print("  可用命令: hello / time / hash <text> / status / exit")
    print("=" * 60)

    while True:
        try:
            cmd = input("\n[demo]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见!")
            break

        if not cmd:
            continue
        elif cmd == "exit":
            print("再见!")
            break
        elif cmd == "hello":
            print("  Hello from DemoSoft! 授权验证已通过。")
        elif cmd == "time":
            print(f"  当前时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        elif cmd.startswith("hash "):
            import hashlib
            text = cmd[5:]
            print(f"  SHA-256({text}) = {hashlib.sha256(text.encode()).hexdigest()}")
        elif cmd == "status":
            # 重新检查状态（每次调用都会重新跑反调试/反VM/存储校验）
            verifier = build_verifier()
            status = verifier.check_status()
            show_status(status)
        else:
            print(f"  未知命令: {cmd}")


def main():
    print(BANNER)

    verifier = build_verifier()

    # ---- 步骤 1: 启动前安全预检（反调试 + 反VM）----
    print("[1/3] 安全预检（反调试 + 反VM）...")
    ok, reason = verifier.preflight()
    if not ok:
        print(f"\n✗ 安全检查失败: {reason}")
        print("  该软件不能在调试器/虚拟机环境中运行。")
        sys.exit(10)
    print("  ✓ 通过")

    # ---- 步骤 2: 检查激活状态 ----
    print("[2/3] 检查激活状态...")
    status = verifier.check_status()
    if not status.is_activated:
        print(f"  ✗ 未激活: {status.failure_reason}")
        if status.is_expired:
            print(f"  之前的授权已于 {time.ctime(status.expires_at)} 过期")
        # 步骤 3: 提示激活
        print("[3/3] 等待用户输入激活码...")
        if not prompt_activation(verifier):
            print("\n✗ 激活失败次数过多，退出。")
            sys.exit(11)
        # 激活成功，重新检查
        status = verifier.check_status()
    else:
        print("  ✓ 已激活")
    show_status(status)

    # ---- 进入主循环 ----
    run_main_work()


if __name__ == "__main__":
    main()
