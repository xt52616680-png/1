"use client";

// 用户管理面板：列出/创建/封禁/解封/删除注册用户，调整套餐与设备数
import { useCallback, useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { UserPlus, Trash2, Ban, CheckCircle2, RefreshCw, Users } from "lucide-react";
import { toast } from "sonner";
import { getAdminKey } from "@/lib/admin-client";

interface MachineInfo {
  id: string;
  fingerprint: string;
  name: string | null;
  lastSeenAt: string | null;
  lastIp: string | null;
}

interface UserInfo {
  id: string;
  email: string;
  plan: string;
  planExpiresAt: string | null;
  maxMachines: number;
  status: string;
  createdAt: string;
  machines: MachineInfo[];
}

export function UsersPanel() {
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPlan, setNewPlan] = useState("TRIAL");
  const [newMachines, setNewMachines] = useState("1");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/auth/users", { headers: { "x-admin-key": getAdminKey() } });
      const j = await res.json();
      if (j.ok) setUsers(j.data);
      else toast.error(j.message || "加载失败（请先在设置里保存管理员密钥）");
    } catch {
      toast.error("网络错误");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const adminUnbind = async (machineId: string) => {
    if (!confirm("确定解绑该设备？客户下次登录将自动重新绑定。")) return;
    const res = await fetch(`/api/auth/users/machine?machineId=${machineId}`, {
      method: "DELETE",
      headers: { "x-admin-key": getAdminKey() },
    });
    const j = await res.json();
    if (j.ok) {
      toast.success("已解绑");
      await load();
    } else {
      toast.error(j.message || "解绑失败");
    }
  };

  const createUser = async () => {
    if (!newEmail || !newPassword) {
      toast.error("请填写邮箱和初始密码");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(newEmail)) {
      toast.error("邮箱格式无效");
      return;
    }
    if (newPassword.length < 8) {
      toast.error("初始密码至少 8 位");
      return;
    }
    setCreating(true);
    try {
      const res = await fetch("/api/auth/users", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-admin-key": getAdminKey() },
        body: JSON.stringify({ email: newEmail, password: newPassword, plan: newPlan, maxMachines: Number(newMachines) || 1 }),
      });
      const j = await res.json().catch(() => null);
      if (j?.ok) {
        toast.success(`已创建：${newEmail}`);
        setNewEmail("");
        setNewPassword("");
        await load();
      } else {
        toast.error(j?.message || `创建失败（HTTP ${res.status}）`);
      }
    } catch (e) {
      toast.error(`网络异常：${String(e).slice(0, 80)}`);
    } finally {
      setCreating(false);
    }
  };

  const patchUser = async (userId: string, data: Record<string, unknown>) => {
    const res = await fetch("/api/auth/users", {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "x-admin-key": getAdminKey() },
      body: JSON.stringify({ userId, ...data }),
    });
    const j = await res.json();
    if (j.ok) {
      toast.success("已更新");
      await load();
    } else {
      toast.error(j.message || "更新失败");
    }
  };

  const deleteUser = async (userId: string, email: string) => {
    if (!confirm(`确定删除用户 ${email}？其设备将全部解绑。`)) return;
    const res = await fetch(`/api/auth/users?userId=${userId}`, {
      method: "DELETE",
      headers: { "x-admin-key": getAdminKey() },
    });
    const j = await res.json();
    if (j.ok) {
      toast.success("已删除");
      await load();
    } else {
      toast.error(j.message || "删除失败");
    }
  };

  const statusBadge = (u: UserInfo) =>
    u.status === "BANNED" ? (
      <Badge variant="destructive">已封禁</Badge>
    ) : (
      <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30">正常</Badge>
    );

  return (
    <div className="space-y-6">
      <Card className="border-white/[0.06]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <UserPlus className="h-5 w-5 text-emerald-400" />
            创建注册用户
          </CardTitle>
          <CardDescription>为客户开通账号：邮箱 + 初始密码 + 套餐 + 设备数（客户用它在客户端登录）</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            <Input placeholder="客户邮箱" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} />
            <Input placeholder="初始密码（≥8位）" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
            <Select value={newPlan} onValueChange={setNewPlan}>
              <SelectTrigger>
                <SelectValue placeholder="套餐" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="TRIAL">试用 TRIAL</SelectItem>
                <SelectItem value="STANDARD">标准 STANDARD</SelectItem>
                <SelectItem value="PRO">专业 PRO</SelectItem>
              </SelectContent>
            </Select>
            <Input placeholder="设备数" value={newMachines} onChange={(e) => setNewMachines(e.target.value)} />
            <Button className="bg-emerald-600 hover:bg-emerald-500" disabled={creating} onClick={createUser}>
              {creating ? "创建中…" : "创建用户"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="border-white/[0.06]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5 text-emerald-400" />
            注册用户列表
            <Button variant="outline" size="sm" className="ml-auto" onClick={load} disabled={loading}>
              <RefreshCw className={"h-4 w-4 mr-1" + (loading ? " animate-spin" : "")} />
              刷新
            </Button>
          </CardTitle>
          <CardDescription>共 {users.length} 个用户。封禁 = 立即无法登录与心跳；删除 = 释放全部设备绑定。</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[460px] pr-3">
            <div className="space-y-3">
              {users.length === 0 && !loading && <p className="text-slate-500 text-sm">暂无用户，先在上面创建一个。</p>}
              {users.map((u) => (
                <div key={u.id} className="rounded-lg border border-white/[0.06] p-3 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-100">{u.email}</span>
                    {statusBadge(u)}
                    <Badge variant="outline">{u.plan}</Badge>
                    <Badge variant="outline">
                      设备 {u.machines.length}/{u.maxMachines}
                    </Badge>
                    {u.planExpiresAt && (
                      <Badge variant="outline">到期 {new Date(u.planExpiresAt).toLocaleDateString("zh-CN")}</Badge>
                    )}
                    <span className="ml-auto text-xs text-slate-500">
                      注册于 {new Date(u.createdAt).toLocaleDateString("zh-CN")}
                    </span>
                  </div>
                  {u.machines.length > 0 && (
                    <div className="text-xs text-slate-500 space-y-0.5">
                      {u.machines.map((m) => (
                        <div key={m.id} className="flex items-center gap-2">
                          <span>
                            📟 {m.name || m.id.slice(0, 8)} · 机器码{" "}
                            <code className="text-emerald-400/80">{m.fingerprint}</code> · 最近活跃{" "}
                            {m.lastSeenAt ? new Date(m.lastSeenAt).toLocaleString("zh-CN") : "从未"} · IP {m.lastIp || "-"}
                          </span>
                          <button
                            className="ml-auto text-rose-400 hover:text-rose-300 underline"
                            onClick={() => adminUnbind(m.id)}
                          >
                            [解绑]
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex flex-wrap items-center gap-2">
                    {u.status === "BANNED" ? (
                      <Button size="sm" variant="outline" onClick={() => patchUser(u.id, { status: "ACTIVE" })}>
                        <CheckCircle2 className="h-4 w-4 mr-1" />
                        解封
                      </Button>
                    ) : (
                      <Button size="sm" variant="outline" onClick={() => patchUser(u.id, { status: "BANNED" })}>
                        <Ban className="h-4 w-4 mr-1" />
                        封禁
                      </Button>
                    )}
                    <Select
                      value={u.plan}
                      onValueChange={(plan) => patchUser(u.id, { plan })}
                    >
                      <SelectTrigger className="h-8 w-[130px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="TRIAL">试用</SelectItem>
                        <SelectItem value="STANDARD">标准</SelectItem>
                        <SelectItem value="PRO">专业</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      className="h-8 w-[90px]"
                      defaultValue={String(u.maxMachines)}
                      onBlur={(e) => {
                        const n = Number(e.target.value);
                        if (n && n !== u.maxMachines) patchUser(u.id, { maxMachines: n });
                      }}
                      placeholder="设备数"
                    />
                    <Input
                      className="h-8 w-[130px]"
                      placeholder="到期日期"
                      type="date"
                      onBlur={(e) => {
                        if (e.target.value) patchUser(u.id, { planExpiresAt: new Date(e.target.value).toISOString() });
                      }}
                    />
                    <Button size="sm" variant="destructive" className="ml-auto" onClick={() => deleteUser(u.id, u.email)}>
                      <Trash2 className="h-4 w-4 mr-1" />
                      删除
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
