"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Loader2, ShieldCheck, Server, Cpu, Activity, AlertTriangle, TrendingUp } from "lucide-react";
import { adminHeaders } from "@/lib/admin-client";

type Stats = {
  totalCodes: number;
  activeCodes: number;
  unusedCodes: number;
  expiredCodes: number;
  revokedCodes: number;
  totalMachines: number;
  totalActivations: number;
  activeActivations: number;
  callbacksToday: number;
  byCardType: Record<string, number>;
};

const CARD_LABELS: Record<string, string> = {
  month: "月卡", season: "季卡", year: "年卡", time: "时卡",
};

export function DashboardPanel() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await fetch("/api/stats", { headers: adminHeaders() });
        const data = await res.json();
        if (res.status === 401 || res.status === 503) {
          setError("管理接口未授权：请到「设置」页配置管理密钥（LICENSE_ADMIN_KEY）");
        } else if (!res.ok) {
          setError(data.error || "加载失败");
        } else {
          setError("");
          setStats(data);
        }
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
    const t = setInterval(fetchStats, 30000);
    return () => clearInterval(t);
  }, []);

  if (loading || !stats) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-500 gap-3">
        {error ? (
          <div className="text-sm text-amber-400">{error}</div>
        ) : (
          <Loader2 className="h-6 w-6 animate-spin" />
        )}
      </div>
    );
  }

  const cards = [
    { label: "总激活码", value: stats.totalCodes, icon: ShieldCheck, color: "text-emerald-400" },
    { label: "激活中", value: stats.activeCodes, icon: Activity, color: "text-emerald-400" },
    { label: "未使用", value: stats.unusedCodes, icon: ShieldCheck, color: "text-slate-300" },
    { label: "已过期", value: stats.expiredCodes, icon: AlertTriangle, color: "text-amber-400" },
    { label: "已吊销", value: stats.revokedCodes, icon: AlertTriangle, color: "text-rose-400" },
    { label: "总机器数", value: stats.totalMachines, icon: Cpu, color: "text-sky-300" },
    { label: "总激活数", value: stats.totalActivations, icon: Server, color: "text-sky-300" },
    { label: "24h 回调", value: stats.callbacksToday, icon: TrendingUp, color: "text-emerald-300" },
  ];

  const cardTypeEntries = Object.entries(stats.byCardType);

  return (
    <div className="space-y-6">
      {/* Stat grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {cards.map((c) => (
          <Card
            key={c.label}
            className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm hover:border-emerald-500/20 transition-colors"
          >
            <CardContent className="p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="text-xs uppercase tracking-wider text-slate-400">
                  {c.label}
                </div>
                <c.icon className={`h-4 w-4 ${c.color}`} />
              </div>
              <div className="text-3xl font-bold tabular-nums text-slate-100">
                {c.value}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Card type breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-base">按卡类型分布</CardTitle>
            <CardDescription>已生成的所有激活码按类型统计</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {cardTypeEntries.length === 0 ? (
              <div className="text-sm text-slate-500 py-8 text-center">
                暂无数据
              </div>
            ) : (
              cardTypeEntries.map(([type, count]) => {
                const pct = stats.totalCodes > 0 ? (count / stats.totalCodes) * 100 : 0;
                return (
                  <div key={type} className="space-y-1.5">
                    <div className="flex justify-between text-sm">
                      <span className="text-slate-300">
                        {CARD_LABELS[type] || type}
                      </span>
                      <span className="font-mono text-emerald-300">
                        {count} ({pct.toFixed(1)}%)
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full bg-emerald-500 rounded-full transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>

        <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="text-base">激活健康度</CardTitle>
            <CardDescription>激活 vs 过期 vs 吊销 占比</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <HealthRow
              label="激活中"
              value={stats.activeActivations}
              total={stats.totalActivations}
              color="bg-emerald-500"
            />
            <HealthRow
              label="已过期"
              value={stats.totalActivations - stats.activeActivations - stats.revokedCodes}
              total={stats.totalActivations}
              color="bg-amber-500"
            />
            <HealthRow
              label="已吊销"
              value={stats.revokedCodes}
              total={stats.totalActivations}
              color="bg-rose-500"
            />
            <div className="mt-4 p-3 rounded-lg bg-slate-950/40 border border-white/[0.06]">
              <div className="text-xs text-slate-400 mb-1">激活率</div>
              <div className="text-2xl font-bold tabular-nums text-emerald-300">
                {stats.totalActivations > 0
                  ? `${((stats.activeActivations / stats.totalActivations) * 100).toFixed(1)}%`
                  : "-"}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function HealthRow({ label, value, total, color }: {
  label: string; value: number; total: number; color: string;
}) {
  const pct = total > 0 ? (value / total) * 100 : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-sm">
        <span className="text-slate-300">{label}</span>
        <span className="font-mono text-slate-400">{value} ({pct.toFixed(1)}%)</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
        <div
          className={`h-full ${color} rounded-full transition-all`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
