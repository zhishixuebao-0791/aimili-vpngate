def update_service():
    print("正在获取远程更新并检测版本...", flush=True)
    if os.path.exists(INSTALL_DIR):
        try:
            os.chdir(INSTALL_DIR)
            if not os.path.exists(".git"):
                print("错误: 当前安装目录不是 Git 仓库，无法通过 Git 更新。")
                time.sleep(3)
                return

            # Fetch remote origin updates
            subprocess.run(["git", "fetch", "--all"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

            local_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            remote_commit = subprocess.run(["git", "rev-parse", f"origin/{branch}"], capture_output=True, text=True).stdout.strip()

            if local_commit == remote_commit:
                print("\n【版本状态】当前已是最新版本，无需更新！")
                override = input("是否强制重新拉取代码并覆盖安装？(y/N): ").strip().lower()
                if override != 'y':
                    print("已取消更新。")
                    time.sleep(1.5)
                    return
            else:
                print(f"\n【检测到更新】本地版本: {local_commit[:8]}，远程最新版本: {remote_commit[:8]}")
                confirm = input("是否确认开始更新并重启服务？(Y/n): ").strip().lower()
                if confirm not in ('', 'y', 'yes'):
                    print("已取消更新。")
                    time.sleep(1.5)
                    return

            print(f"\n正在强制重置本地代码至 origin/{branch} ...", flush=True)
            subprocess.run(["git", "reset", "--hard", f"origin/{branch}"], check=True)
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
