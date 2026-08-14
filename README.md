# Frp 自动化流水线

[![Fork 原版](https://img.shields.io/badge/Fork-原版仓库-blue?style=flat-square&logo=github)](https://github.com/fatedier/frp)
[![构建状态](https://img.shields.io/github/actions/workflow/status/MoTeam-cn/Frp/release.yml?style=flat-square&logo=githubactions&label=构建)](https://github.com/MoTeam-cn/Frp/actions)
[![最新版本](https://img.shields.io/github/v/tag/MoTeam-cn/Frp?style=flat-square&logo=git&label=版本)](https://github.com/MoTeam-cn/Frp/tags)
[![下载量](https://img.shields.io/github/downloads/MoTeam-cn/Frp/total?style=flat-square&logo=github&label=下载)](https://github.com/MoTeam-cn/Frp/releases)

## 流程

1. Fork 原版仓库 [fatedier/frp](https://github.com/fatedier/frp)
2. Action 每小时检查上游 tag 更新
3. 发现新版后自动拉取代码并打包 Release
4. 通过 PUT 上传程序到存储桶
5. 更新云端 frpc_version.json 配置信息

## 技术栈

- GitHub Actions
- Shell / Python
- MinIO / S3
- JSON

---

Fork → 追更 → 构建 → 上传 → 更新
