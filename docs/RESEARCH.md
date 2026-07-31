# 运营商广告劫持技术原理调研

本文档支撑 AdJustice 的设计决策。所有引用均链接至公开来源。

## 1. 劫持规模与背景

威胁猎人 2026 年 Q2 报告（<https://www.czta.org.cn/muying/41327.html>）：
被黑产劫持的智能电视和电视盒子在恶意流量中，**账号身份与广告相关流量合计
占比高达 69.7%**。智能大屏是黑产系统化攻击的明确目标。

## 2. 主要劫持技术对比

| 技术 | 原理 | 触发位置 | AdJustice 应对 |
|---|---|---|---|
| DNS 劫持 | ISP DNS 服务器返回伪造 IP | DNS 解析环节 | UDP 直查可信 DNS 比对 |
| TCP 旁路干扰 | 在线路上抢先发送伪造 HTTP 响应 | TCP 数据流 | 截图证据 + DNS 旁证 |
| HTTP 透明代理 | 在代理层注入 JS 或替换响应 | HTTP 转发环节 | 截图 + DNS 旁证 |
| 缓存污染 | 缓存服务器返回旧的或被篡改内容 | 缓存节点 | 截图证据 |

无论劫持通过何种技术发生，**最终效果**都是：用户在正常广告时段看到的画面
被替换成了非法内容。所以 AdJustice 选择**仅以屏幕截图为核心证据**——
完全免疫于劫持手段的变化。

## 3. 关键论文与报告

### 3.1 TCP 旁路干扰（最核心的劫持技术）

**腾讯安全应急响应中心** "链路劫持攻击一二三"：
<https://security.tencent.com/index.php/blog/msg/10>

> "运营商的路由器节点上设置协议检测，一旦发现是HTTP请求...抢在原始目标
> Server 之前发送伪造的响应。"

关键揭示：

-   劫持设备可以基于 TCP 序列号的具体值伪造 RST/FIN/PSH+ACK 包。
-   达到分段覆盖的"先到者赢得客户端"现象。
-   通过 TTL 比较可以定位劫持设备的位置。

**binss 的中国联通 TCP 旁路干扰分析**：
<https://www.binss.me/blog/analyse-the-tcp-bypass-hijacking-of-china-unicom/>

> "通过握手建立信道，并在信道上进行数据传输的方式这给中间人带来了可乘之机。
> 中间人保存各TCP连接的连接信息...根据所抓取的TCP数据包更新该连接信息
> 中的请求方向TCP等待序列号和应答方向TCP等待序列号。"

### 3.2 HTTP 透明代理

**Mingming Zhang et al.** "Measuring Privacy Threats in China-Wide Mobile
Networks" (Foci '18): <https://zhangmm.net/publication/foci18-chinawidemobilenetworks/>

> "HTTP transparent proxies are widely deployed in mobile networks and...
> contents of web pages can be modified by proxy devices, which are
> replaced by or injected with advertisements."

### 3.3 DNS 解析路径拦截

**Liu et al.** "Who Is Answering My Queries: Understanding and
Characterizing Interception of the DNS Resolution Path"
(USENIX Security '18):
<https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-liu_0.pdf>

> "On-path devices intercept DNS queries sent to public DNS, and
> surreptitiously respond with DNS answers resolved by alternative
> recursive nameservers instead."

> ASes of China Mobile have significantly higher interception ratio
> than ASes of other Chinese ISPs.

### 3.4 中国电信网络直投广告实战分析

**王晓磊** "中国电信劫持HTTP流量强插广告"：
<http://quotation.github.io/web/2015/04/15/china-telecom-isp-hijack.html>

> "ISP 篡改了托管在七牛 CDN 上的 JS 文件，将其替换为自家的广告代码，
> 同时在文件里重新请求原 JS 以掩盖痕迹。"

> "目前 ISP 的做法是只劫持 JS 文件。"

### 3.5 性能对抗：内容层防御

**0x0d.im** "用 CSP 防御运营商劫持"：
<https://0x0d.im/posts/anti-internet-traffic-hijacking-by-csp/>

通过 Content-Security-Policy 白名单发现页面中未列入白名单的资源请求，
作为劫持检测。在服务端聚合后可总结出劫持多发的运营商与省份。

## 4. 我们对核心技术的应对策略

```text
劫持者       ：拥有网络基础设施，可以主动注入伪装内容
AdJustice    ：只能看到最终结果（屏幕上显示的内容）

不对称战斗   ：唯一可靠的检测点是"电视屏幕上出现的是什么"
              → 这是 AdJustice 设计的基础
```

### 4.1 截图 → 用户判断

无论劫持是 DNS、TCP 还是 HTTP 代理完成，App 收到的"广告素材"是什么，
屏幕渲染的就是什么。截图能产生不受劫持技术影响的证据。

### 4.2 QR 码 → 硬证据

非法广告几乎都需要用户操作（扫码付款、扫码入群、扫码下载）。这些二维码
本身就是可追溯的资金/身份标识。ZXing 解码 → **不可抵赖的实证链**。

### 4.3 DNS 检测 → 旁证

虽然 DNS 不是对所有劫持类型都有效（HTTP 透明代理可能跳过 DNS 环节），
但 DNS 劫持是国内最常见的形式。比对系统 DNS 与可信 DNS 的解析结果，
提供独立的旁证据。

### 4.4 三类证据交叉验证

```
 截图(视觉证据)     ←  "用户看到了什么"
 QR内容(资金证据)   ←  "黑产在哪里收钱"
 DNS检测结果(网络证据) ← "网络层有没有被动过手脚"
```

三者并存 → 单证不足时互相补强 → 形成不可抵赖的证据链。

## 5. 调研结论对设计的关键影响

| 调研结论 | AdJustice 设计选择 |
|---|---|
| 劫持方式多样且会持续演化 | 不依赖任何特定劫持技术做主检测 |
| DNS 劫持在国内是最常见形式 | 加强 DNS 检测作为旁证 |
| 用户的电视屏幕是检测结果唯一可信的反馈点 | 以截图为核心证据 |
| 二维码是非法广告资金链的关键节点 | ZXing 解码成为关键证据来源 |
| 运营商在中国有网络设备绝对控制权，加密是最好的防线 | APK 自身做最小化数据收集，全本地存储 |

## 6. 扩展方向（如果社区贡献）

-   **域名清单在线更新**。维护一个可信域名与已知 CDN IP 段的对照表。
-   **设备端 TTL 检测**。在 Android 设备上实现 TCP 包 TTL 检测（需要 root）。
-   **CSP 类型的本地检测**。但电视 App 不开放 WebView 内容，这条路只能走着看。
-   **群众互助**：用户匿名提交事件元数据（仅 DNS 结果与时间，不含截图）到
    开源托管端，绘制全国运营商劫持热力图。AdJustice v1 暂不实现，等 v2。
