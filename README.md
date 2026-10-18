# macOS 原生更新安装器 helper

这个目录是可独立复制到公开 GitHub 仓库的完整源码工程。C helper 使用 macOS 系统 API，GitHub Actions 生成包含 x86_64 与 arm64 的 universal2 Mach-O。最低部署目标为 Intel macOS 10.13、Apple Silicon macOS 11.0；这些是编译目标，最低系统的运行兼容性仍需实机验收。

## 建立独立仓库并取得产物

1. 新建一个公开 GitHub 仓库。把**本目录的整个内容复制到新仓库根目录**，包括隐藏目录 **.github/workflows**、.gitignore、.gitattributes、installer.c、test_installer.py 和本 README。不要再套一层 MacUpdateInstaller 目录；复制后应能看到仓库根的 installer.c 和 .github/workflows/build.yml。
2. 提交并推送源码到新仓库。在 **Actions → Build macOS native updater → Run workflow** 手动启动；main/master 上相关源码 push 和 pull request 也会触发。新仓库若尚未显示工作流，先确认工作流已提交到默认分支并启用 Actions。
3. 等待编译、签名验证、Python 回归和打包全部成功。下载 **HostUtilities-macOS-universal2** artifact，先解开 GitHub 提供的 artifact ZIP，得到 HostUtilities-macOS-universal2.tar.gz、SHA256SUMS、build-info.json。
4. 在 macOS 的同一下载目录运行以下命令。SHA256SUMS 验证 tar 和外部构建信息；tar 内的 build-info.json 还记录二进制 SHA-256。

   ~~~sh
   shasum -a 256 -c SHA256SUMS
   mkdir helper-unpacked
   tar -xzf HostUtilities-macOS-universal2.tar.gz -C helper-unpacked
   codesign --verify --strict --verbose=2 helper-unpacked/HostUtilities.Installer
   lipo helper-unpacked/HostUtilities.Installer -verify_arch x86_64 arm64
   ~~~

5. 把**解出的 HostUtilities.Installer 二进制**放到 MOD 主仓库的 **native/UpdateInstaller/macos/HostUtilities.Installer**，然后重新编译主仓库 MOD，使其嵌入新 helper。主仓库构建使用本地已提供的二进制，不会联网构建或下载这个 helper。经 macOS 复制时保留 0755 执行权限；主仓库运行时仍需按现有流程设置提取文件的执行权限。

这里的工作流只有 contents: read 权限，无 Secrets、无 Release 发布。构建不需要访问 MOD 私有仓库。签名是 codesign -s - 的 **ad-hoc 本地签名**，没有开发者证书和 Apple 公证；签名校验成功不等于 Gatekeeper 放行。

## 构建、回归与证据

Actions 固定使用一个 macos-14 runner：分别编译两种架构，以 lipo 合并，ad-hoc 签名后校验签名与架构。编译启用 -Wall -Wextra -Werror -Wno-deprecated-declarations。Python 回归运行合并后的真实二进制，**只执行 runner 本机架构**，不宣称双架构都已运行，也不依赖 Rosetta。build-info.json 记录源码 commit SHA、installer.c 摘要、协议、编译器、SDK、最低系统版本、架构、实际执行测试架构、二进制摘要和 Actions run 链接。

有 Mac 时可在独立仓库根目录运行，不需要安装 Python 第三方包：

~~~sh
python3 test_installer.py --binary dist/package/HostUtilities.Installer
# 使用自行解压的二进制及指定证据目录：
python3 test_installer.py --binary helper-unpacked/HostUtilities.Installer --workspace dist/tests --timeout 12
~~~

默认在 dist/tests 下为每轮创建唯一 run-* 临时目录，--workspace 可指定其他专用测试父目录。每个用例在该目录中创建自己的 BepInEx/plugins 和 cache，不读取或修改真实游戏。owner 是短暂的真实 Python 子进程，PID/创建时间与文件元数据均由实际 helper 查询。所有启动均使用参数数组，不调用 shell。夹具不创建 restart.flag，因此不会请求 Steam 启动。退出或失败时仅回收本轮创建的子进程。

回归覆盖普通替换及元数据/备份、owner 存活期间不改文件、有效 owner 下重放拒绝、授权前后取消、授权后的文件改写拒绝、目标符号链接和后置父目录链接拒绝、第二个安装目标冲突后的真实回滚、元字符与 Unicode（含非 BMP 字符）路径，以及普通 .DS_Store 更新后保留、含该元数据的旧目录保留、同名链接拒绝和 Windows 协议魔数拒绝。回滚断言要求新文件转移到 failed-new 恢复副本、旧文件恢复原字节及元数据，不能仅凭失败退出码判定回滚通过。

每个查询、握手和退出都有超时，超时记为失败。所有夹具、install.plan、握手标记、apply.log、query-*.log、unittest.log、results.jsonl、summary.json 及恢复副本都保留在会话目录，不自动删除历史证据。测试目录被 Git 忽略。Actions 即使失败也尝试将已有的 dist/tests 和 dist/load-commands.txt 打包为 **HostUtilities-macOS-test-evidence.tar.gz**，再上传到 **HostUtilities-macOS-test-evidence** artifact；tar 保留测试中的特殊字符文件名、隐藏文件（含 .DS_Store 夹具）和符号链接，避免上传器的文件名限制。下载并解开 artifact ZIP 后，请在 macOS 上用 `tar -xzf HostUtilities-macOS-test-evidence.tar.gz` 提取证据；其中的双引号等文件名不兼容 Windows 文件系统。正式 artifact 使用 tar 保存执行权限，不依赖 artifact ZIP 恢复权限。

## 独立协议 OC2MAC1

macOS magic 是八字节 **OC2MAC1\0**，与 Windows 的 OC2UPD1 独立。虽然记录顺序沿用 Windows 布局，macOS attributes 字段表示 **POSIX mode & 0777**，时间表示 **FILETIME 100ns**；不能传入 Windows 文件属性或直接用托管 Process.StartTime 代替原生创建时间。

所有整数为小端。字符串为 u32 UTF-16 code unit 数后接 UTF-16LE 数据（不是 UTF-8 字节数）。根记录依次为 magic[8]、u32 owner PID、i64 owner creation FILETIME、u32 cleanup、五个字符串（cache boundary、plugin boundary、plugins、cache、current DLL）、u32 group count。每组依次为 checks、moves、installs、directories、prune；每个列表前有 u32 数量。Entry 依次为 u32 kind、path/saved/hash 字符串、u32 mode、i64 mtime、i64 size、u32 children。检查 kind 0/1/2/3 分别表示不存在、文件、目录清单、目录存在。

- 无参数运行：从二进制相邻目录读取 install.plan。该目录必须是 plan.cache 的真子目录；安全边界以下禁止符号链接。测试把 plugins/cache 放在同一真实 BepInEx 边界内。
- --metadata PATH：只读查询普通文件，stdout 严格为十进制 **mode FILETIME** 加 LF。
- --owner PID：只读查询真实进程，stdout 严格为十进制 **creation FILETIME** 加 LF。查询模式不读取计划、不写握手标记，也不脱离终端。

安装流程校验计划和精确 owner 身份，写 started.flag 防重放，再发布 ready.flag；owner 存活时等待 armed.flag，确认后发布 authorized.flag，使用 kqueue NOTE_EXIT 观察该 owner 退出，随后复核并执行 checks/moves/installs/directories/prune。ready、armed、authorized、cancel 标记的文件内容分别严格为 ready\r\n、armed\r\n、authorized\r\n、cancel\r\n（此处反斜杠表示实际 CRLF 字节）。撤销、无效标记、超时、路径或链接违规、冻结输入变化都会拒绝或中止执行；日志和恢复副本保留供排查。不要重放失败计划，应由 MOD 重新生成计划。

## 尚待真实环境验收

Windows 上只维护源码，不把静态检查算成 Mac 运行通过。Actions 通过后仅能证明当前 runner 上的构建、签名/架构/打包验证及所列临时目录回归。仍须在真实 Intel / Apple Silicon Mac 分别验收：最低系统、Gatekeeper/quarantine、Rosetta、原生 BepInEx 加载、MOD/资源更新、权限与受限卷/跨卷、Steam 重启以及进程树终止等。当前 helper 的 ad-hoc 签名不保证这些环境可以直接执行；关闭 CrossOver 瓶子或终止整个进程树仍可能杀死更新工具。
