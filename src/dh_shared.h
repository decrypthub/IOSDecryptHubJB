// dh_shared.h — 管理器 App 与 updater daemon 的共享约定
//
// 单一事实源（两边只认这些路径与键，不各自发明）：
//   名单: 管理器写 /var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist
//         （App 一定写得动）以及 cfprefsd 域 com.iosdecrypthub.loader / enabledBundles
//         沙盒目标进程读不到这份 prefs，必须再有一份 jb 配置：
//         <bootstrap>/usr/lib/IOSDecryptHub/config/enabledBundles.plist
//         rootless 上 App 可直接写 jb；rootHide 上 App/daemon Mach-O 对 /usr/lib 是
//         EPERM，由 updated.sh（launchd 的 /bin/sh）把 prefs 拷过去。
//         loader：prefs 读到数组就用；读不到再回退 jb。空数组=全关。
//   引擎: <bootstrap>/usr/lib/IOSDecryptHub/decrypt_helper.dylib
//         仅由 dpkg 随完整 deb 安装，管理器和 daemon 不单独替换。
//   元信息: <bootstrap>/usr/lib/IOSDecryptHub/version.plist              {version, variant, arch}
//   状态: DH_STATE_PATH（mobile 可写）；引擎目录里的 state.plist 仅作 rootless 兼容镜像
//   请求: DH_REQUEST_PATH
//         (mobile 可写，daemon 读；launchd 用 WatchPaths 监听它；内容不可信，
//          daemon 只取有限 action；check 查询规范 APT 源，安装交给包管理器)
//         action: check / restart / stop / set-enabled / none
//         兼容接收旧 install / rollback，但明确拒绝并提示使用包管理器
//         bundle:  可选，restart / stop 要操作的 App（bundle id）
//                  restart = 结束进程并尽量重新打开；stop = 只结束进程
//         enabledBundles: set-enabled 时的完整名单（字符串数组；内容不可信，daemon 只收 NSString）

#define DH_DOMAIN_LOADER  @"com.iosdecrypthub.loader"
#define DH_KEY_BUNDLES    @"enabledBundles"

// 相对 bootstrap 根目录。旧值少了 usr/lib/，App 会写到 <jbroot>/IOSDecryptHub/...，
// 开关表现为「写入启用名单失败」。
#define DH_CONFIG_REL     @"usr/lib/IOSDecryptHub/config/enabledBundles.plist"
#define DH_ENGINE_NAME    @"decrypt_helper.dylib"
#define DH_VERSION_FILE   @"version.plist"
#define DH_STATE_FILE     @"state.plist"

#define DH_REQUEST_PATH   @"/var/mobile/Library/Preferences/com.iosdecrypthub.updater.request.plist"
// roothide 下 App 对 /var/mobile 的原子写可能被容器映射/权限挡住；jb config 是
// App 一定可写的路径。App 双写，updated.sh 在启动 daemon 前把它转交到 DH_REQUEST_PATH。
#define DH_REQUEST_JB_REL @"usr/lib/IOSDecryptHub/config/updater.request.plist"
// App 自己的共享缓存目录（postinst 已 chown mobile + 0777），是 roothide 下
// 最可靠的请求投递点；launchd 监听它，updated.sh 转交到 DH_REQUEST_PATH。
#define DH_REQUEST_CACHE_PATH @"/var/mobile/Library/Caches/com.iosdecrypthub/updater.request.plist"
#define DH_LOADER_PREFS   @"/var/mobile/Library/Preferences/com.iosdecrypthub.loader.plist"
#define DH_STATE_PATH     @"/var/mobile/Library/Preferences/com.iosdecrypthub.updater.state.plist"
#define DH_LOCK_PATH      @"/var/mobile/Library/Preferences/com.iosdecrypthub.updated.lock"
#define DH_JB_LOCK_REL    @"var/log/com.iosdecrypthub.updated.lock"
#define DH_JB_STATE_REL   @"var/log/com.iosdecrypthub.updater.state.plist"
#define DH_NOTIFY_STATE   @"com.iosdecrypthub.updater.state"

#define DH_REQ_CHECK      @"check"
#define DH_REQ_INSTALL    @"install"
#define DH_REQ_ROLLBACK   @"rollback"
#define DH_REQ_RESTART    @"restart"
#define DH_REQ_STOP       @"stop"
#define DH_REQ_SET_ENABLED @"set-enabled"
#define DH_REQ_NONE       @"none"
