// hook_webkit.h — WKWebView 宿主侧观测入口

#ifndef DH_HOOK_WEBKIT_H
#define DH_HOOK_WEBKIT_H

#ifdef __cplusplus
extern "C" {
#endif

// 在 WebKit 已加载或后续加载时安装宿主侧 WKWebView 观测。
// 只使用 ObjC runtime swizzle，不进入 WebContent/Networking 进程。
void dh_install_webkit_hooks(void);

#ifdef __cplusplus
}
#endif

#endif // DH_HOOK_WEBKIT_H
