// DecryptHelperApp.swift — 解密助手管理器 (越狱独立 App)
// 功能: 列出所有已装 App, 选择注入目标, 开关控制
// 偏好写入: /var/jb/var/mobile/Library/Preferences/com.dh.decrypthelper.plist

import SwiftUI

@main
struct DecryptHelperApp: App {
    var body: some Scene {
        WindowGroup {
            MainView()
        }
    }
}
