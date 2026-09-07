"use client";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { GeneratePanel } from "@/components/keygen/generate-panel";
import { StatusPanel } from "@/components/keygen/status-panel";
import { DashboardPanel } from "@/components/keygen/dashboard-panel";
import { SettingsPanel } from "@/components/keygen/settings-panel";
import { Shield, Lock } from "lucide-react";

export default function HomePage() {
  return (
    <div className="min-h-screen bg-slate-950 max-w-7xl mx-auto p-6 lg:p-8">
      {/* Sticky header */}
      <header className="sticky top-0 z-10 -mx-6 lg:-mx-8 px-6 lg:px-8 py-4 mb-6 bg-slate-950/80 backdrop-blur-md border-b border-white/[0.06]">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-emerald-500/30 blur-xl rounded-full" />
              <div className="relative h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                <Shield className="h-5 w-5 text-emerald-400" />
              </div>
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-100">
                License Keygen Console
              </h1>
              <p className="text-xs text-slate-500">
                Ed25519 · Anti-Debug · Anti-VM · Multi-Layer Storage
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-2 text-xs">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
              <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>系统运行中</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900/60 border border-white/[0.06] text-slate-400">
              <Lock className="h-3 w-3" />
              <span>Ed25519 已配置</span>
            </div>
          </div>
        </div>
      </header>

      {/* Tabs */}
      <Tabs defaultValue="generate" className="space-y-6">
        <TabsList className="bg-slate-900/60 border border-white/[0.06] p-1 h-auto">
          <TabsTrigger
            value="generate"
            className="data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-300 data-[state=active]:shadow-none rounded-md px-4 py-1.5 text-sm"
          >
            生成激活码
          </TabsTrigger>
          <TabsTrigger
            value="status"
            className="data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-300 data-[state=active]:shadow-none rounded-md px-4 py-1.5 text-sm"
          >
            状态查看
          </TabsTrigger>
          <TabsTrigger
            value="dashboard"
            className="data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-300 data-[state=active]:shadow-none rounded-md px-4 py-1.5 text-sm"
          >
            仪表盘
          </TabsTrigger>
          <TabsTrigger
            value="settings"
            className="data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-300 data-[state=active]:shadow-none rounded-md px-4 py-1.5 text-sm"
          >
            设置
          </TabsTrigger>
        </TabsList>

        <TabsContent value="generate" className="space-y-6 mt-0">
          <GeneratePanel />
        </TabsContent>

        <TabsContent value="status" className="space-y-6 mt-0">
          <StatusPanel />
        </TabsContent>

        <TabsContent value="dashboard" className="space-y-6 mt-0">
          <DashboardPanel />
        </TabsContent>

        <TabsContent value="settings" className="space-y-6 mt-0">
          <SettingsPanel />
        </TabsContent>
      </Tabs>

      {/* Footer */}
      <footer className="mt-12 pt-6 border-t border-white/[0.06] text-xs text-slate-500 flex flex-wrap items-center justify-between gap-3">
        <div>
          License SDK v1.0 · Ed25519 + AES-256-GCM · 12 项反调试 · 11 项反VM · 5 层分布式存储
        </div>
        <div className="font-mono">
          sha256(CPU ∪ MB ∪ Disk ∪ MAC) → fingerprint_hash
        </div>
      </footer>
    </div>
  );
}
