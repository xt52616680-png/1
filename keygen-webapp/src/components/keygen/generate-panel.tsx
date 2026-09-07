"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Loader2, Copy, Check, Shield, Clock, Calendar, CalendarDays, CalendarRange, Hourglass } from "lucide-react";
import { toast } from "sonner";
import {
  CARD_LABELS,
  CARD_DESCRIPTIONS,
  CARD_DEFAULT_DURATIONS,
  type CardType,
} from "@/lib/keygen-shared";
import { adminHeaders } from "@/lib/admin-client";

const CARD_ICONS: Record<CardType, React.ReactNode> = {
  month: <Calendar className="h-4 w-4" />,
  season: <CalendarRange className="h-4 w-4" />,
  year: <CalendarDays className="h-4 w-4" />,
  time: <Hourglass className="h-4 w-4" />,
};

export function GeneratePanel() {
  const [cardType, setCardType] = useState<CardType>("month");
  const [customDays, setCustomDays] = useState<number>(7);
  const [maxMachines, setMaxMachines] = useState<number>(1);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setResult(null);
    setCopied(false);
    try {
      const body: any = {
        cardType,
        maxMachines,
        note: note || undefined,
      };
      if (cardType === "time") body.customDays = customDays;

      const res = await fetch("/api/keygen/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...adminHeaders() },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (res.status === 401 || res.status === 503) {
        throw new Error("管理接口未授权：请先到「设置」页配置管理密钥（LICENSE_ADMIN_KEY）");
      }
      if (!res.ok) throw new Error(data.error || "生成失败");
      setResult(data);
      toast.success("激活码生成成功");
    } catch (e: any) {
      toast.error(e.message || "生成失败");
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result?.fullCode) return;
    navigator.clipboard.writeText(result.fullCode);
    setCopied(true);
    toast.success("已复制到剪贴板");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Generation Form */}
      <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Shield className="h-5 w-5 text-emerald-400" />
            生成激活码
          </CardTitle>
          <CardDescription>
            选择卡类型 → 自动签名 → 生成 Ed25519 签名激活码
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Card type selector (radio group, single-select) */}
          <div className="space-y-3">
            <Label className="text-xs uppercase tracking-wider text-slate-400">
              卡类型（单选）
            </Label>
            <RadioGroup
              value={cardType}
              onValueChange={(v) => setCardType(v as CardType)}
              className="grid grid-cols-2 gap-3"
            >
              {(Object.keys(CARD_LABELS) as CardType[]).map((ct) => (
                <label
                  key={ct}
                  htmlFor={`card-${ct}`}
                  className={`flex flex-col gap-2 rounded-lg border p-4 cursor-pointer transition-all
                    ${cardType === ct
                      ? "border-emerald-500/60 bg-emerald-500/[0.08] shadow-[0_0_0_1px_rgba(16,185,129,0.3)]"
                      : "border-white/[0.06] bg-slate-900/40 hover:border-white/[0.12] hover:bg-slate-900/60"
                    }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-sm font-medium">
                      {CARD_ICONS[ct]}
                      {CARD_LABELS[ct]}
                    </div>
                    <RadioGroupItem value={ct} id={`card-${ct}`} />
                  </div>
                  <div className="text-xs text-slate-400">
                    {CARD_DESCRIPTIONS[ct]}
                  </div>
                </label>
              ))}
            </RadioGroup>
          </div>

          {/* Custom days (only for time card) */}
          <div className={`space-y-2 transition-all ${
            cardType === "time" ? "opacity-100" : "opacity-40 pointer-events-none"
          }`}>
            <Label htmlFor="custom-days" className="text-xs uppercase tracking-wider text-slate-400">
              时卡自定义天数（1-3650）
            </Label>
            <Input
              id="custom-days"
              type="number"
              min={1}
              max={3650}
              value={customDays}
              onChange={(e) => setCustomDays(parseInt(e.target.value) || 0)}
              disabled={cardType !== "time"}
              className="font-mono bg-slate-950/50 border-white/[0.08]"
            />
          </div>

          {/* Max machines */}
          <div className="space-y-2">
            <Label htmlFor="max-machines" className="text-xs uppercase tracking-wider text-slate-400">
              最大激活机器数
            </Label>
            <Input
              id="max-machines"
              type="number"
              min={1}
              max={10}
              value={maxMachines}
              onChange={(e) => setMaxMachines(Math.max(1, parseInt(e.target.value) || 1))}
              className="font-mono bg-slate-950/50 border-white/[0.08] w-32"
            />
          </div>

          {/* Note */}
          <div className="space-y-2">
            <Label htmlFor="note" className="text-xs uppercase tracking-wider text-slate-400">
              备注（可选）
            </Label>
            <Input
              id="note"
              placeholder="例如：客户A / 内部测试"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              className="bg-slate-950/50 border-white/[0.08]"
            />
          </div>

          <Separator className="bg-white/[0.06]" />

          {/* Summary */}
          <div className="rounded-lg bg-slate-950/40 border border-white/[0.06] p-4 space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-400">类型</span>
              <span className="font-medium">{CARD_LABELS[cardType]}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">有效期</span>
              <span className="font-mono text-emerald-300">
                {cardType === "time"
                  ? `${customDays} 天`
                  : `${CARD_DEFAULT_DURATIONS[cardType]} 天 (强制)`}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">最大机器数</span>
              <span className="font-mono">{maxMachines}</span>
            </div>
          </div>

          <Button
            onClick={handleGenerate}
            disabled={loading || (cardType === "time" && (!customDays || customDays < 1))}
            className="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-medium shadow-[0_0_20px_-5px_rgba(16,185,129,0.5)]"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                生成中...
              </>
            ) : (
              <>
                <Shield className="h-4 w-4" />
                生成激活码
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Result display */}
      <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="text-base">激活码结果</CardTitle>
          <CardDescription>
            复制此码发给客户。码内嵌 Ed25519 签名，软件端会验证签名防止伪造。
          </CardDescription>
        </CardHeader>
        <CardContent>
          {result ? (
            <div className="space-y-4">
              {/* Code reveal box */}
              <div className="relative rounded-lg border border-emerald-500/30 bg-emerald-500/[0.04] p-4 shadow-[0_0_30px_-10px_rgba(16,185,129,0.4)]">
                <div className="text-xs uppercase tracking-wider text-emerald-400 mb-2">
                  激活码
                </div>
                <ScrollArea className="max-h-32">
                  <div className="font-mono text-[13px] text-emerald-200 break-all leading-relaxed pr-8">
                    {result.fullCode}
                  </div>
                </ScrollArea>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={handleCopy}
                  className="absolute top-2 right-2 h-8 w-8 p-0 text-slate-400 hover:text-emerald-300"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-emerald-400" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>

              {/* Metadata grid */}
              <div className="grid grid-cols-2 gap-3 text-sm">
                <Meta label="Code ID" value={result.codeId} mono />
                <Meta label="卡类型" value={CARD_LABELS[result.cardType as CardType]} />
                <Meta label="有效期" value={`${result.durationDays} 天`} mono />
                <Meta label="最大机器" value={`${result.maxMachines}`} mono />
                <Meta
                  label="签发时间"
                  value={new Date(result.issuedAt * 1000).toLocaleString("zh-CN")}
                />
                <Meta
                  label="过期时间"
                  value={new Date(result.expiresAt * 1000).toLocaleString("zh-CN")}
                />
              </div>

              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopy}
                  className="border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10"
                >
                  <Copy className="h-4 w-4" />
                  复制激活码
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setResult(null)}
                  className="text-slate-400"
                >
                  清除
                </Button>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-64 text-slate-500 gap-3">
              <Clock className="h-12 w-12 opacity-30" />
              <div className="text-sm">尚未生成激活码</div>
              <div className="text-xs text-slate-600">
                在左侧选择卡类型并点击"生成激活码"
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Meta({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-lg bg-slate-950/40 border border-white/[0.06] p-3">
      <div className="text-xs text-slate-400 mb-1">{label}</div>
      <div className={`text-sm ${mono ? "font-mono text-emerald-300" : "text-slate-200"}`}>
        {value}
      </div>
    </div>
  );
}
