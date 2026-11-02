def latest_release_tag():
    """返回本地仓库中最新的发行版标签 vX.Y.Z（按版本号比较，排除 V2026.06.16 等旧日期标签）。"""
    import re
    res = subprocess.run(["git", "-C", INSTALL_DIR, "tag", "-l"], capture_output=True, text=True)
    best = None
    for tag in res.stdout.split():
        m = re.fullmatch(r"v(\d{1,3})\.(\d+)\.(\d+)", tag)
        if m:
            key = tuple(int(x) for x in m.groups())
            if best is None or key > best[0]:
                best = (key, tag)
    return best[1] if best else ""

def installed_app_version():
    """读取已安装代码的版本号：优先 APP_VERSION 常量，其次当前提交上的 vX.Y.Z 标签，都没有时返回“未知版本”。"""
    import re
    try:
        with open(os.path.join(INSTALL_DIR, "vpngate_manager.py"), encoding="utf-8") as f:
            m = re.search(r'^APP_VERSION\s*=\s*"([^"]+)"', f.read(), re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    res = subprocess.run(["git", "-C", INSTALL_DIR, "describe", "--tags", "--exact-match"], capture_output=True, text=True)
    tag = res.stdout.strip()
    if res.returncode == 0 and re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        return tag[1:]
    return "未知版本"

def update_service():
    print("正在获取远程更新并检测版本...", flush=True)
    if os.path.exists(INSTALL_DIR):
        try:
            os.chdir(INSTALL_DIR)
            if not os.path.exists(".git"):
                print("错误: 当前安装目录不是 Git 仓库，无法通过 Git 更新。")
                time.sleep(3)
                return

            # 拉取远程分支与版本标签（--force 保证远程重打的标签也能同步）
            subprocess.run(["git", "fetch", "--all", "--tags", "--force"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Detect remote branch (prefer current local branch, fallback to origin/main or origin/master)
            curr = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True)
            branch = curr.stdout.strip() if curr.returncode == 0 else ""
            if not branch or branch == "HEAD":
                branch = "main"
                for b in ["main", "master"]:
                    chk = subprocess.run(["git", "rev-parse", "--verify", f"origin/{b}"], capture_output=True, text=True)
                    if chk.returncode == 0:
                        branch = b
                        break

            # 更新目标为最新发行版标签 vX.Y.Z；仓库尚无发行版标签时回退到 origin/<分支>
            release_tag = latest_release_tag()
            target = release_tag or f"origin/{branch}"
            local_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            remote_commit = subprocess.run(["git", "rev-parse", f"{target}^{{commit}}"], capture_output=True, text=True).stdout.strip()
            if not remote_commit:
                print(f"错误: 无法解析更新目标 {target}，请检查网络后重试。")
                time.sleep(3)
                return
            local_label = f"{installed_app_version()} ({local_commit[:8]})"
            remote_label = f"{release_tag} ({remote_commit[:8]})" if release_tag else f"{target} ({remote_commit[:8]})"

            if local_commit == remote_commit:
                print(f"\n【版本状态】当前已是最新发行版 {local_label}，无需更新！")
                override = input("是否强制重新拉取代码并覆盖安装？(y/N): ").strip().lower()
                if override != 'y':
                    print("已取消更新。")
                    time.sleep(1.5)
                    return
            else:
                print(f"\n【检测到更新】本地版本: {local_label}，远程最新发行版: {remote_label}")
                confirm = input("是否确认开始更新并重启服务？(Y/n): ").strip().lower()
                if confirm not in ('', 'y', 'yes'):
                    print("已取消更新。")
                    time.sleep(1.5)
                    return

            print(f"\n正在强制重置本地代码至 {target} ...", flush=True)
            subprocess.run(["git", "reset", "--hard", target], check=True)
            mark_login_refresh_required("ml update")

            # Clean up python cache files
            print("正在清理 Python 缓存 (pycache)...", flush=True)
            subprocess.run(["find", ".", "-type", "d", "-name", "__pycache__", "-exec", "rm", "-rf", "{}", "+"], check=False)

            print("代码拉取成功，正在重新运行安装脚本...", flush=True)
            subprocess.run(["bash", "install.sh", "zhishixuebao-0791", "aimili-vpngate"])
            print("更新已完成！")
            time.sleep(2)
        except Exception as e:
            print(f"更新失败: {e}")
            time.sleep(4)
    else:
        print(f"未找到安装目录: {INSTALL_DIR}")
        time.sleep(2)
