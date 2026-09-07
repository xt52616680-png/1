"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Loader2, RefreshCw, Search, Activity, Clock, Globe, Server, Fingerprint, Hourglass } from "lucide-react";
import { toast } from "sonner";
import { adminHeaders } from "@/lib/admin-client";

type Activation = {
  id: string;
  codeId: string;
  fullCode: string;
  cardType: string;
  durationDays: number;
  fingerprintHash: string;
  fingerprintShort: string;
  activatedAt: string;
  expiresAt: string;
  lastCallbackAt: string | null;
  lastIp: string;
  status: string;
  remainingDays: number;
};

const CARD_LABELS: Record<string, string> = {
  month: "月卡", season: "季卡", year: "年卡", time: "时卡",
};

const STATUS_VARIANT: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  active: "default",
  expired: "secondary",
  revoked: "destructive",
};

const STATUS_LABEL: Record<string, string> = {
  active: "激活中",
  expired: "已过期",
  revoked: "已吊销",
};

export function StatusPanel() {
  const [activations, setActivations] = useState<Activation[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter !== "all") params.set("status", filter);
      const res = await fetch(`/api/activations?${params}`, { headers: adminHeaders() });
      const data = await res.json();
      if (res.status === 401 || res.status === 503) {
        setError("管理接口未授权：请到「设置」页配置管理密钥（LICENSE_ADMIN_KEY）");
        setActivations([]);
      } else {
        setError("");
        setActivations(data.activations || []);
      }
    } catch (e: any) {
      toast.error(e.message || "加载失败");
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    // Defer the initial fetch so setState is not called synchronously in the effect.
    const initial = setTimeout(fetchData, 0);
    const t = setInterval(fetchData, 30000); // auto-refresh every 30s
    return () => {
      clearTimeout(initial);
      clearInterval(t);
    };
  }, [fetchData]);

  const filtered = activations.filter(a => {
    if (!search) return true;
    const s = search.toLowerCase();
    return a.codeId.toLowerCase().includes(s)
        || a.fullCode.toLowerCase().includes(s)
        || a.fingerprintHash.toLowerCase().includes(s)
        || a.lastIp.toLowerCase().includes(s);
  });

  return (
    <Card className="border-white/[0.06] bg-slate-900/60 backdrop-blur-sm">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-5 w-5 text-emerald-400" />
              已激活机器状态
            </CardTitle>
            <CardDescription>
              实时显示所有已激活的机器码、IP、激活码类型、激活时间、剩余时间
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Select value={filter} onValueChange={setFilter}>
              <SelectTrigger className="w-32 bg-slate-950/50 border-white/[0.08]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部状态</SelectItem>
                <SelectItem value="active">激活中</SelectItem>
                <SelectItem value="expired">已过期</SelectItem>
                <SelectItem value="revoked">已吊销</SelectItem>
              </SelectContent>
            </Select>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
              <Input
                placeholder="搜索 IP/机器码/激活码..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 w-64 bg-slate-950/50 border-white/[0.08]"
              />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={fetchData}
              disabled={loading}
              className="border-white/[0.08] hover:bg-slate-800"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCw className="h-4 w-4" />
              )}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <ScrollArea className="max-h-[640px] rounded-lg border border-white/[0.06]">
          <Table>
            <TableHeader>
              <TableRow className="border-white/[0.06] hover:bg-transparent">
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  激活码 / Code ID
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  <Fingerprint className="inline h-3 w-3 mr-1" />
                  机器码
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  <Globe className="inline h-3 w-3 mr-1" />
                  登录 IP
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  类型
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  <Clock className="inline h-3 w-3 mr-1" />
                  激活时间
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  <Hourglass className="inline h-3 w-3 mr-1" />
                  剩余时间
                </TableHead>
                <TableHead className="text-xs uppercase tracking-wider text-slate-400">
                  状态
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {error ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-amber-400 py-12 text-sm">
                    {error}
                  </TableCell>
                </TableRow>
              ) : filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-slate-500 py-12">
                    {loading ? "加载中..." : "暂无激活记录"}
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((a) => (
                  <TableRow
                    key={a.id}
                    className="border-white/[0.06] hover:bg-emerald-500/[0.03] transition-colors"
                  >
                    <TableCell>
                      <div className="font-mono text-xs text-emerald-300">
                        {a.codeId}
                      </div>
                      <div className="font-mono text-[10px] text-slate-500 mt-0.5 max-w-[200px] truncate">
                        {a.fullCode.substring(0, 40)}...
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="font-mono text-xs text-slate-300">
                        {a.fingerprintShort}...
                      </div>
                      <div className="font-mono text-[10px] text-slate-500 mt-0.5">
                        SHA-256(4 因子)
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="font-mono text-xs text-slate-300">
                        {a.lastIp}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {a.lastCallbackAt
                          ? `上报: ${new Date(a.lastCallbackAt).toLocaleString("zh-CN", { hour12: false })}`
                          : "未上报"}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {CARD_LABELS[a.cardType] || a.cardType}
                      </Badge>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {a.durationDays} 天
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="text-xs text-slate-300">
                        {new Date(a.activatedAt).toLocaleString("zh-CN", { hour12: false })}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className={`font-mono text-sm font-medium ${
                        a.status === "active"
                          ? (a.remainingDays <= 3 ? "text-amber-400" : "text-emerald-300")
                          : "text-slate-500"
                      }`}>
                        {a.status === "active" ? `${a.remainingDays} 天` : "-"}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        到期: {new Date(a.expiresAt).toLocaleDateString("zh-CN")}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={STATUS_VARIANT[a.status] || "outline"}>
                        {STATUS_LABEL[a.status] || a.status}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>

        <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
          <div>共 {filtered.length} 条记录</div>
          <div className="flex items-center gap-1">
            <Server className="h-3 w-3" />
            自动刷新 30s
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
