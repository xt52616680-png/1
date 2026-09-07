"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Copy, Key, Download, ShieldAlert, ExternalLink, Lock } from "lucide-react";
import { toast } from "sonner";
import { getAdminKey, setAdminKey } from "@/lib/admin-client";

export function SettingsPanel() {
  // Both pubKey and keygenUrl are stable per session; use lazy initializers
  // so we don't trigger an effect->setState cycle.
  const [pubKey, setPubKey] = useState<string>(
    () => process.env.NEXT_PUBLIC_LICENSE_ED25519_PUBKEY_B64 || "加载中..."
  );
  const [keygenUrl] = useState<string>(
    () => typeof window !== "undefined" ? window.location.origin : ""
  );
  const [adminKeyInput, setAdminKeyInput] = useState<string>("");
  const [adminKeySaved, setAdminKeySaved] = useState<string>(
    () => getAdminKey()
  );

  // The public key is public by design - fetch it from the keygen so the
  // page works even without NEXT_PUBLIC_LICENSE_ED25519_PUBKEY_B64.
  useEffect(() => {
    let cancelled = false;
    fetch("/api/pubkey")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!cancelled && d?.public_key_b64) setPubKey(d.public_key_b64);
        else if (!cancelled && !process.env.NEXT_PUBLIC_LICENSE_ED25519_PUBKEY_B64)
          setPubKey("(无法获取，请检查服务端密钥配置)");
      })
      .catch(() => {
        if (!cancelled && !process.env.NEXT_PUBLIC_LICENSE_ED25519_PUBKEY_B64)
          setPubKey("(无法获取，请检查服务端密钥配置)");
      });
    return () => { cancelled = true; };
  }, []);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} 已复制`);
  };

  const saveAdminKey = () => {
    const key = adminKeyInput.trim();
    if (!key) {
      toast.error("请输入管理密钥");
      return;
    }
    setAdminKey(key);
    setAdminKeySaved(key);
    setAdminKeyInput("");
    toast.success("管理密钥已保存到本机浏览器");
  };

  const clearAdminKey = () => {
    setAdminKey("");
    setAdminKeySaved("");
    toast.success("已清除本机保存的管理密钥");
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Key className="h-5 w-5 text-emerald-400" />
            加密密钥
          </CardTitle>
          <CardDescription>
            Ed25519 非对称密钥对。公钥嵌入软件 SDK，私钥仅保留在注册机后端。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>公钥 (PUBLIC KEY)</Label>
              <Badge variant="outline" className="text-emerald-300 border-emerald-500/30">
                可公开
              </Badge>
            </div>
            <div className="relative">
              <pre className="rounded-lg bg-slate-950/60 border border-white/[0.06] p-3 pr-10 font-mono text-xs text-emerald-300 break-all whitespace-pre-wrap">
                {pubKey}
              </pre>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyToClipboard(pubKey, "公钥")}
                className="absolute top-2 right-2 h-7 w-7 p-0"
              >
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="text-xs text-slate-500">
              此公钥需配置到 Python SDK 的 <code className="text-emerald-400">LicenseConfig.public_key_b64</code>。
              客户端用它验证激活码签名，无法伪造。
            </div>
          </div>

          <Separator className="bg-white/[0.06]" />

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>私钥 (PRIVATE KEY)</Label>
              <Badge variant="destructive" className="bg-rose-500/20 text-rose-300 border-rose-500/30">
                <ShieldAlert className="h-3 w-3 mr-1" />
                机密 - 永不外泄
              </Badge>
            </div>
            <div className="rounded-lg bg-rose-950/20 border border-rose-500/20 p-3 text-xs text-rose-300">
              私钥存储在服务器环境变量 <code>LICENSE_ED25519_PRIVATE_KEY_B64</code> 中，
              用于签发激活码。请勿通过任何方式输出到客户端。
            </div>
          </div>

          <Separator className="bg-white/[0.06]" />

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>管理密钥 (ADMIN KEY)</Label>
              {adminKeySaved ? (
                <Badge variant="outline" className="text-emerald-300 border-emerald-500/30">
                  已配置
                </Badge>
              ) : (
                <Badge variant="outline" className="text-amber-300 border-amber-500/30">
                  未配置
                </Badge>
              )}
            </div>
            <div className="rounded-lg bg-amber-950/20 border border-amber-500/20 p-3 text-xs text-amber-300">
              生成 / 状态 / 仪表盘等管理接口需要 <code>x-admin-key</code> 头。
              在此填入与服务端环境变量 <code>LICENSE_ADMIN_KEY</code> 相同的值
              （仅保存在本机浏览器，不会上传）。
            </div>
            <div className="flex items-center gap-2">
              <Input
                type="password"
                placeholder={adminKeySaved ? "••••••••（已保存，可输入新值覆盖）" : "输入 LICENSE_ADMIN_KEY 的值"}
                value={adminKeyInput}
                onChange={(e) => setAdminKeyInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") saveAdminKey(); }}
                className="flex-1 font-mono bg-slate-950/50 border-white/[0.08]"
              />
              <Button size="sm" onClick={saveAdminKey} className="bg-emerald-500 hover:bg-emerald-400 text-slate-950">
                <Lock className="h-3.5 w-3.5 mr-1" />
                保存
              </Button>
              {adminKeySaved && (
                <Button size="sm" variant="ghost" onClick={clearAdminKey} className="text-slate-400">
                  清除
                </Button>
              )}
            </div>
          </div>

          <Separator className="bg-white/[0.06]" />

          <div className="space-y-2">
            <Label>注册机服务地址 (KEYGEN URL)</Label>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded-lg bg-slate-950/60 border border-white/[0.06] p-3 font-mono text-xs text-slate-300 break-all">
                {keygenUrl}
              </code>
              <Button
                size="sm"
                variant="ghost"
                onClick={() => copyToClipboard(keygenUrl, "URL")}
              >
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="text-xs text-slate-500">
              客户端 SDK 配置 <code className="text-emerald-400">LICENSE_KEYGEN_URL</code> 环境变量指向此地址。
              生产环境建议部署到 Vercel/Cloudflare 免费层，无需自购 VPS。
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Download className="h-5 w-5 text-emerald-400" />
            SDK & 集成
          </CardTitle>
          <CardDescription>
            下载 Python SDK 集成到您的软件
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg bg-slate-950/40 border border-white/[0.06] p-4">
            <div className="text-sm font-medium text-slate-200 mb-2">
              Python SDK
            </div>
            <div className="text-xs text-slate-400 mb-3">
              位于 <code className="text-emerald-400">download/license-sdk-python/</code>，
              包含完整源码、示例软件、密钥生成工具。
            </div>
            <div className="space-y-1.5">
              <FileItem name="license_sdk/" desc="核心 SDK 模块" />
              <FileItem name="example_app.py" desc="集成示例软件" />
              <FileItem name="generate_keypair.py" desc="密钥对生成工具" />
            </div>
          </div>

          <div className="rounded-lg bg-slate-950/40 border border-white/[0.06] p-4">
            <div className="text-sm font-medium text-slate-200 mb-2">
              快速集成步骤
            </div>
            <ol className="text-xs text-slate-400 space-y-2 list-decimal list-inside">
              <li>在软件启动时调用 <code className="text-emerald-400">LicenseVerifier.preflight()</code> 检查反调试/反VM</li>
              <li>调用 <code className="text-emerald-400">check_status()</code> 读取本地激活态</li>
              <li>未激活则提示用户输入激活码，调用 <code className="text-emerald-400">activate(code)</code></li>
              <li>启动后台线程每 6 小时调用 <code className="text-emerald-400">do_callback()</code> 上报状态</li>
              <li>生产环境通过 PyArmor/Nuitka 编译保护字节码</li>
            </ol>
          </div>

          <Separator className="bg-white/[0.06]" />

          <div className="rounded-lg bg-amber-950/20 border border-amber-500/20 p-3 text-xs text-amber-300">
            <div className="font-medium mb-1">⚠ 反破解建议</div>
            <ul className="space-y-1 list-disc list-inside opacity-90">
              <li>启用 <code>refuse_in_vm=True</code> 拒绝在虚拟机运行</li>
              <li>使用 PyArmor 企业版做字节码虚拟化（最强）</li>
              <li>关键函数加 <code>@check_license</code> 装饰器，多处校验</li>
              <li>定期更换 <code>FINGERPRINT_SALT</code>（会让旧激活失效，谨慎）</li>
              <li>生产部署建议加 VMProtect/Themida 二次加壳</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-xs uppercase tracking-wider text-slate-400">{children}</div>
  );
}

function FileItem({ name, desc }: { name: string; desc: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <code className="text-emerald-300 font-mono">{name}</code>
      <span className="text-slate-500">{desc}</span>
    </div>
  );
}
