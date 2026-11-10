# 可选服务器运维工具

`crl_cache.py` 是 2026-11-10 生产服务器的独立 OpenVPN CRL 缓存工具源码备份，未接入通用安装器，不会因仓库常规更新自动启用。依赖 Linux/systemd cgroup v2、Python 3.10+、OpenVPN 2.5+ 和 OpenSSL 3.0+。

生产部署路径 `/opt/aimili-crl/refresh.py`，`aimili-crl-refresh.timer` 每六小时运行，带随机延迟；oneshot 限 CPU 15%、内存 96MiB、启动时间 120 秒。只抓当前出口的证书链，独立连接使用 `dev=null`、禁路由/DNS/网卡操作，在认证前主动退出，不重启业务隧道。

从经过系统 CA 和 server 用途检查的证书链读取 Let's Encrypt CRL 地址，限制下载域名和大小；核验 CRL 签名、有效期，再原子更新 `store`。系统 CA 仅链接到缓存，未把抓到的远端证书添加为信任根。更新失败保留上次缓存并记录错误；已过期缓存不会被移除以绕过校验。最多留三代缓存。状态在 `/opt/aimili-crl/status.json`，失败还写入 systemd journal。

OpenSSL 3.0 的 `openssl crl -verify` 在签名错误时可能仍返回 0，因此必须同时要求 `verify OK`；已通过真实篡改签名、错误签发者和过期数据负例。不能仅凭命令退出码判断签名正确。源码依据：[OpenSSL 3.0 apps/crl.c](https://github.com/openssl/openssl/blob/openssl-3.0/apps/crl.c)。

管理器的可选环境变量 `AIMILI_OPENVPN_CAPATH` 指向包含原有 CA 哈希链接和 `.rN` CRL 的目录。未配置时仍使用系统 CA 目录；显式配置的目录不存在时停止该次连接，避免静默忽略配置。保留 `remote-cert-tls server`、`route-nopull` 和原路由分工。

这采用 OpenVPN 的原生行为：适用的 CRL 可检查撤销/过期，缺失相应 CRL 的其他证书链仍可能警告并继续。并未增加全出口“缺 CRL 就拒绝”的额外策略，也不保证任意第三方 CA 均被本工具覆盖。新吊销信息是否影响已经建立的连接，取决于后续 TLS 校验；不是主动踢除全部既有连接。依据：[OpenVPN 2.6 capath 手册](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)。

当前服务器已验证一个现用出口和三个备用出口；这不代表未来所有免费出口均可用。定时刷新不会替换代理核心、订阅账号或节点入口 IP。
