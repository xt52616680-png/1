"""
demo_trial_paid.py - 试用 + 付费双模式示例
==========================================

演示如何实现"试用 7 天 + 付费激活"的双模式软件。
- 首次启动：进入 7 天试用期（无需激活码）
- 试用期内：所有功能可用，但显示剩余试用天数
- 试用过期：必须输入激活码才能继续使用
- 付费激活后：永久/卡类型对应天数使用，无试用提示

适用场景：商业化软件、共享软件、先试用后付费模式

运行：
    cd /home/z/my-project/download/license-sdk-python/demos
    python demo_trial_paid.py
"""

from __future__ import annotations

import functools
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from license_sdk import LicenseVerifier, LicenseConfig


# ---------------------------------------------------------------------------
# 试用模式配置
# ---------------------------------------------------------------------------

TRIAL_DAYS = 7  # 试用天数

# 试用状态文件（隐藏在 ProgramData）
def _trial_file() -> str:
    base = os.environ.get("ProgramData", "/tmp")
    d = os.path.join(base, "Microsoft", "DeviceSync")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "trial.json")


# ---------------------------------------------------------------------------
# 试用管理器
# ---------------------------------------------------------------------------

class TrialManager:
    """
    试用期管理：首次启动记录开始时间，之后每次启动检查剩余天数。
    防篡改：用机器指纹签名试用状态文件。
    """

    def __init__(self, verifier: LicenseVerifier):
        self.verifier = verifier

    def _load_state(self):
        try:
            with open(_trial_file(), "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None

    def _save_state(self, state: dict) -> bool:
        try:
            with open(_trial_file(), "w") as f:
                json.dump(state, f)
            return True
        except OSError:
            return False

    def get_or_start_trial(self):
        """
        返回 (is_in_trial, remaining_days, message)。
        - 首次调用：创建试用状态，返回 (True, TRIAL_DAYS, "试用开始")
        - 后续调用：返回 (True, 剩余天数, ...)
        - 已过期：返回 (False, 0, "试用已过期")
        """
        state = self._load_state()
        if state is None:
            # 首次启动试用
            now = int(time.time())
            state = {
                "started_at": now,
                "expires_at": now + TRIAL_DAYS * 86400,
                "fingerprint": self._current_fingerprint(),
            }
            self._save_state(state)
            return True, TRIAL_DAYS, "试用开始"

        # 已存在试用记录
        now = int(time.time())
        if now > state["expires_at"]:
            return False, 0, "试用已过期"
        remaining = max(0, (state["expires_at"] - now) // 86400)
        return True, remaining, "试用中"

    def _current_fingerprint(self) -> str:
        """生成当前机器的简单指纹（用于防试用文件被复制到其他机器）。"""
        from license_sdk import fingerprint as fp_module
        comps = fp_module.collect_components()
        return fp_module.components_short_hash(comps)

    def clear_trial(self) -> bool:
        try:
            os.remove(_trial_file())
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# 双模式验证器
# ---------------------------------------------------------------------------

class DualModeLicense:
    """统一管理试用模式 + 付费模式。"""

    def __init__(self):
        cfg = LicenseConfig(
            public_key_b64=os.environ.get(
                "LICENSE_ED25519_PUBKEY_B64",
                LicenseConfig().public_key_b64,
            ),
            keygen_url=os.environ.get("LICENSE_KEYGEN_URL", "http://localhost:3000"),
            software_version="demo-trial-1.0.0",
            refuse_in_vm=False,
        )
        self.verifier = LicenseVerifier(cfg)
        self.trial = TrialManager(self.verifier)

    def check(self) -> dict:
        """
        检查授权状态。
        返回:
          {
            "mode": "paid" | "trial" | "expired",
            "remaining_days": int,
            "code_id": str | None,
            "card_type": str | None,
            "message": str,
          }
        """
        # 1. 先检查付费激活
        status = self.verifier.check_status()
        if status.is_activated:
            return {
                "mode": "paid",
                "remaining_days": status.remaining_days,
                "code_id": status.code_id,
                "card_type": status.card_type,
                "message": f"付费授权 ({status.card_type})",
            }

        # 2. 再检查试用
        in_trial, days, msg = self.trial.get_or_start_trial()
        if in_trial:
            return {
                "mode": "trial",
                "remaining_days": days,
                "code_id": None,
                "card_type": None,
                "message": msg,
            }

        # 3. 都没有 -> 过期
        return {
            "mode": "expired",
            "remaining_days": 0,
            "code_id": None,
            "card_type": None,
            "message": "试用已过期，请购买激活码",
        }

    def activate(self, code: str):
        return self.verifier.activate(code)


# ---------------------------------------------------------------------------
# 双模式装饰器
# ---------------------------------------------------------------------------

def feature(requires_paid: bool = False):
    """
    装饰器：标注功能的访问级别。
    - requires_paid=False: 试用也可用
    - requires_paid=True: 仅付费用户可用
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            state = self.license.check()
            if state["mode"] == "expired":
                raise PermissionError(f"试用已过期，无法使用 {func.__name__}")
            if requires_paid and state["mode"] != "paid":
                raise PermissionError(f"{func.__name__} 仅付费用户可用")
            return func(self, *args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# 模拟软件
# ---------------------------------------------------------------------------

class DemoSoft:
    """模拟一个有免费功能 + 付费功能的软件。"""

    def __init__(self):
        self.license = DualModeLicense()

    def show_status(self):
        state = self.license.check()
        print("\n" + "=" * 60)
        if state["mode"] == "paid":
            print(f"  [付费版] {state['message']}")
            print(f"  激活码: {state['code_id']}  类型: {state['card_type']}")
            print(f"  剩余天数: {state['remaining_days']} 天")
        elif state["mode"] == "trial":
            print(f"  [试用版] {state['message']}")
            print(f"  剩余试用天数: {state['remaining_days']} 天 / {TRIAL_DAYS} 天")
            print(f"  购买激活码以解锁永久使用")
        else:
            print(f"  [已过期] {state['message']}")
            print(f"  请输入激活码以继续使用")
        print("=" * 60)

    # ---- 免费功能（试用也可用） ----

    @feature(requires_paid=False)
    def basic_read(self, file: str) -> str:
        """基础读取：试用版也能用。"""
        return f"读取 {file} 的内容（基础功能）"

    @feature(requires_paid=False)
    def basic_search(self, keyword: str) -> list:
        """基础搜索：试用版也能用。"""
        return [f"匹配项 {i}: {keyword}" for i in range(3)]

    # ---- 付费功能（仅付费版可用） ----

    @feature(requires_paid=True)
    def advanced_export(self, data: str, fmt: str = "pdf") -> str:
        """高级导出：仅付费版。"""
        return f"导出 {len(data)} 字节为 {fmt.upper()} 格式"

    @feature(requires_paid=True)
    def batch_process(self, items: list) -> list:
        """批量处理：仅付费版。"""
        return [f"批处理-{i}-{x}" for i, x in enumerate(items)]

    @feature(requires_paid=True)
    def premium_support(self) -> str:
        """优先技术支持：仅付费版。"""
        return "📞 您已接入优先技术支持队列"

    # ---- 激活入口 ----

    def prompt_activate(self) -> bool:
        code = input("  激活码: ").strip()
        if not code:
            return False
        ok, msg = self.license.activate(code)
        if ok:
            print(f"  ✓ {msg}")
            return True
        print(f"  ✗ {msg}")
        return False


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  Trial + Paid Demo - 试用 + 付费双模式")
    print("=" * 60)

    app = DemoSoft()

    # 安全预检
    ok, reason = app.license.verifier.preflight()
    if not ok:
        print(f"\n✗ 安全检查失败: {reason}")
        sys.exit(10)

    app.show_status()

    # 演示各功能
    print("\n--- 免费功能（试用也可用） ---")
    try:
        print("basic_read:", app.basic_read("test.txt"))
        print("basic_search:", app.basic_search("hello"))
    except PermissionError as e:
        print(f"✗ {e}")

    print("\n--- 付费功能（仅付费版） ---")
    try:
        print("advanced_export:", app.advanced_export("data", "pdf"))
    except PermissionError as e:
        print(f"✗ {e}")
        print("  (需要付费激活才能使用)")

    try:
        print("batch_process:", app.batch_process([1, 2, 3]))
    except PermissionError as e:
        print(f"✗ {e}")

    # 提供激活入口
    state = app.license.check()
    if state["mode"] != "paid":
        print("\n--- 激活入口 ---")
        print("  输入激活码升级到付费版（或回车跳过）")
        if app.prompt_activate():
            app.show_status()
            # 重新尝试付费功能
            print("\n--- 重新调用付费功能 ---")
            try:
                print("advanced_export:", app.advanced_export("data", "pdf"))
                print("batch_process:", app.batch_process([1, 2, 3]))
                print("premium_support:", app.premium_support())
            except PermissionError as e:
                print(f"✗ {e}")

    print("\n" + "=" * 60)
    print("  Demo 完成")
    print("=" * 60)


if __name__ == "__main__":
    main()
