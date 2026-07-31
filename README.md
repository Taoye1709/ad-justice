# AdJustice

> 国产互联网电视广告劫持的**主动拦截**工具。开源，仅本地运行，无任何 AI 模型，不收集任何数据。

AdJustice 在电视上建立本地 HTTP 代理，拦截运营商（ISP）注入的非法广告
（保健品、赌博、诱导充值、可疑二维码……），同时保留取证能力：
每次拦截都会在本地生成结构化证据，可用于向运营商 / 12321 投诉。

## 背景：运营商广告劫持

部分宽带网络存在**系统性的 DNS 劫持 + HTTP 注入**（实测证据见
[docs/ISP_DNS_HIJACK_REPORT.md](docs/ISP_DNS_HIJACK_REPORT.md)）：

1. 运营商在 **UDP 53 明文 DNS 通道**上篡改所有公共 DNS 服务器的响应
   （223.5.5.5 / 114.114.114.114 / 8.8.8.8 等均被污染，TCP 53 / DoH 正常）
2. 视频 App 的广告域名被解析到**海外广告服务器 IP**（实测：委内瑞拉、
   加纳、乌克兰的运营商 IP）
3. 广告流量被透明代理接管，注入非法广告替换正常广告

## 工作原理

```
启动 AdJustice → 点「开始监控」
        │
        ▼
本地 HTTP 代理 (127.0.0.1:8898)  +  设置系统全局代理
        │
        ├─ 明文 HTTP 响应 → InjectionDetector 检测注入签名
        │    命中 → 替换为空响应 + 写入本地证据
        │
        ├─ HTTPS (CONNECT) 隧道 → 目标域名/IP 黑名单检查
        │    命中（如 miaozhen.com 广告 SDK）→ 拒绝建立隧道
        │
        └─ 上游域名解析 → 走 TCP 53（绕过 UDP 污染）
             解析到黑名单 IP → 阻断 + 记录证据
```

### 检测能力

| 层 | 机制 | 说明 |
|---|---|---|
| HTTP 响应 | 注入签名检测 | `Via: 1.1`、`X-Cache`、赌博/诈骗关键词等 |
| HTTPS 隧道 | 域名黑名单 | 广告 SDK 域名（如 `miaozhen.com`）直接拒连 |
| DNS 解析 | TCP 53 解析 | 绕过 ISP 的 UDP DNS 污染 |
| IP 层 | 广告 IP 黑名单 | 实测的海外广告服务器 IP 直接阻断 |

## 安装

从 [Releases](../../releases) 下载 APK（最新版 v1.0.0：
<https://github.com/Taoye1709/ad-justice/releases/download/v1.0.0/app-debug.apk>），
通过 U 盘或文件传输安装到电视。

> **首次使用需要授权**（一次性，通过 adb）：
>
> ```bash
> adb connect <电视IP>:5555
> adb shell pm grant com.adjustice android.permission.WRITE_SECURE_SETTINGS
> ```
>
> 该权限用于让 App 设置系统全局代理。不授予也可用，但需在电视
> 系统设置中手动把代理指向 `127.0.0.1:8898`。

## 编译

### 方式一：本地编译（需要 JDK 17 + Android SDK）

```bash
git clone https://github.com/Taoye1709/ad-justice.git
cd ad-justice
./gradlew assembleDebug
```

输出位于 `app/build/outputs/apk/debug/`。

### 方式二：GitHub Actions 自动编译

1. Push 任意 commit 到 main → 自动触发编译
2. 在 Actions 页面下载 `AdJustice-debug-apk.zip` 工件
3. 解压得到 `app-debug.apk`

## 证据目录

每次拦截写入 `<filesDir>/adj_evidence/hijack_log.jsonl`，每条包含：

```json
{
  "id": 8,
  "time": "2026-07-31 17:18:44",
  "type": "tunnel-domain",
  "match": "tencent-dtv.m.cn.miaozhen.com",
  "host": "tencent-dtv.m.cn.miaozhen.com",
  "headers": "HTTP/1.1 200 OK ..."
}
```

- `type`：拦截类型（`signature` 注入签名 / `tunnel-domain` 广告域名 /
  `blocked-ip` 广告 IP）
- `host`：目标域名
- `headers`：响应头（含注入特征，可作投诉证据）

## 举报渠道

证据确认后，建议并行提交：

1. **12321 网络不良与垃圾信息举报中心**：<https://www.12321.cn/>
2. **工信部电信用户申诉受理中心**：<https://yhss.miit.gov.cn/>
3. 运营商客服：电信 10000 / 联通 10010 / 移动 10086

## 技术背景

完整实测诊断报告：[docs/ISP_DNS_HIJACK_REPORT.md](docs/ISP_DNS_HIJACK_REPORT.md)

## 协议

GPL-3.0-or-later。任何人均可自由使用、修改、再分发，但修改后的代码亦须开源。

## 贡献

欢迎贡献：广告域名/IP 黑名单更新、更多注入特征、电视厂商 ROM 适配补丁。
请通过 GitHub Issues / Pull Requests 提交。
