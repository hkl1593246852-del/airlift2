# AirLift2

基于 `sandbox_extension_issue_file` 不强制 `SANDBOX_EXTENSION_NOFOLLOW` 的沙盒越界读写 PoC（iOS 15+，未越狱）。纯 GitHub Actions 打包，本地不需要 Mac。

## 原理

1. 在容器内建符号链接 `l -> s`（`s` 是容器内真实文件，必然合法）
2. `sandbox_extension_issue_file("com.apple.app-sandbox.read", l, 0)` 拿到 token
3. `unlink(l)` 后重建 `l -> 目标文件`（沙盒外）
4. `sandbox_extension_consume(token)` 消费
5. 通过 `l` 读写，内核只比对 token 路径，不复验解析后的真实目标

没有内存破坏、不需要竞态，确定性复现。

## 目录

```
Sources/main.m            主程序（UIKit，带日志界面）
Sources/Info.plist        bundle 配置
scripts/build.sh          macOS 构建 + 打包 ipa
.github/workflows/build.yml  GitHub Actions 自动打包
```

## 打包（不需要本地 Mac）

```bash
git init && git add . && git commit -m init
gh repo create airlift2 --private --source=. --push
# 或者网页上新建仓库后 git remote add origin ... && git push -u origin main
```

推送后进仓库 **Actions → build-ipa → 最新一次运行 → Artifacts → AirLift2-ipa**，下载得到 `AirLift2.ipa`。

## 安装（Windows）

1. 装 [Sideloadly](https://sideloadly.io/) + iTunes（要 Apple Mobile Device 驱动）
2. 连手机，把 `AirLift2.ipa` 拖进去，填 Apple ID，Start
3. 手机上 设置 → 通用 → VPN与设备管理 → 信任你的开发者证书
4. 打开 AirLift2 → 等日志刷完

免费 Apple ID 签名 7 天过期，到期重装。

## 它会打印什么

```
[1] baseline: read /etc/passwd without escape   -> blocked
[2] escaped read /etc/passwd                    -> OK  N bytes
[3] escaped read .GlobalPreferences.plist       -> OK / FAILED
[4] list other app containers                   -> N 个 UUID -> bundle id
[5] escaped write /var/tmp                      -> OK / FAILED
```

`[1]` 是基线：不越界时读不到。`[2]` 开始才是逃逸后的结果。

## 判定

| 现象 | 含义 |
|---|---|
| [1] blocked 且 [2] OK | 漏洞成立，沙盒边界被绕过 |
| [1] [2] 都 blocked | 该版本已修，或类名不对 |
| [2] OK [4] 空 | 容器枚举被额外拦，单文件读仍可用 |
| [5] OK | read-write 扩展同样受影响，可写沙盒外 |

## 注意

- 只在自有设备上跑，别拿去测别人的机器
- `[5]` 会写一个 `/var/tmp/cl-*.bin` 然后删掉，不碰已有文件
- iOS 17+ 的 `Data Protection` 会让部分文件在锁屏时读不到，跑之前先解锁
