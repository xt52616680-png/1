/**
 * /api/update/download — 客户端更新包下载。
 * v1：安装包未上传时返回 501 + 说明；管理侧将最新安装包放入 Vercel 环境配置的
 * 对象存储（或后续 R2）后，此处改为 302 签名 URL。
 */
import { NextResponse } from 'next/server';

export const runtime = 'nodejs';

export async function GET() {
  const installerUrl = process.env.LATEST_INSTALLER_URL || '';
  if (!installerUrl) {
    return NextResponse.json(
      { ok: false, code: 'NO_UPDATE_PACKAGE', message: '更新包暂未发布，请联系管理员获取最新安装包' },
      { status: 501 },
    );
  }
  return NextResponse.redirect(installerUrl, 302);
}
