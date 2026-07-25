// PrivateAPIs.swift — 私有框架声明 (越狱环境可用)
// LSApplicationWorkspace: 枚举已安装应用

import UIKit
import Foundation

// MARK: - LSApplicationWorkspace (MobileCoreServices / FrontBoard)
@objc protocol LSApplicationWorkspacePrivate {
    func allInstalledApplications() -> [Any]
    func privateURLSchemes() -> [Any]
}

class LSAppInfo: NSObject {
    @objc var applicationIdentifier: String { "" }
    @objc var localizedName: String? { nil }
    @objc var bundleURL: URL? { nil }
    @objc var shortVersionString: String? { nil }
    @objc var isSystemApplication: Bool { false }
    @objc var isDeletable: Bool { false }
}

// MARK: - 动态加载私有 API
struct AppEnumerator {
    static func allApps() -> [AppInfo] {
        var results: [AppInfo] = []

        // 方法 1: LSApplicationWorkspace (最可靠)
        if let workspaceClass = NSClassFromString("LSApplicationWorkspace") {
            let workspace = (workspaceClass as AnyObject).perform(Selector(("defaultWorkspace")))?.takeUnretainedValue()
            if let apps = workspace?.perform(Selector(("allInstalledApplications")))?.takeUnretainedValue() as? [AnyObject] {
                for proxy in apps {
                    let bid = proxy.perform(Selector(("applicationIdentifier")))?.takeUnretainedValue() as? String ?? ""
                    let name = proxy.perform(Selector(("localizedName")))?.takeUnretainedValue() as? String ?? bid
                    let isSystem = (proxy.perform(Selector(("isSystemApplication")))?.takeUnretainedValue() as? Bool) ?? false
                    let bundleURL = proxy.perform(Selector(("bundleURL")))?.takeUnretainedValue() as? URL

                    // 跳过系统关键进程
                    let skip = ["com.apple.springboard", "com.apple.backboardd",
                                "com.apple.Preferences", "com.apple.ioshidd"]
                    if skip.contains(bid) { continue }

                    let icon = bundleURL.flatMap { loadIcon(from: $0) }
                    results.append(AppInfo(
                        bundleId: bid,
                        name: name,
                        isSystem: isSystem,
                        icon: icon
                    ))
                }
            }
        }

        // 方法 2: 扫描 /var/containers/Bundle/Application (fallback)
        if results.isEmpty {
            let base = "/var/containers/Bundle/Application"
            if let dirs = try? FileManager.default.contentsOfDirectory(atPath: base) {
                for d in dirs {
                    let appDir = "\(base)/\(d)"
                    if let items = try? FileManager.default.contentsOfDirectory(atPath: appDir),
                       let appBundle = items.first(where: { $0.hasSuffix(".app") }) {
                        let plistPath = "\(appDir)/\(appBundle)/Info.plist"
                        if let plist = NSDictionary(contentsOfFile: plistPath) {
                            let bid = plist["CFBundleIdentifier"] as? String ?? ""
                            let name = plist["CFBundleDisplayName"] as? String
                                ?? plist["CFBundleName"] as? String ?? bid
                            let icon = loadIcon(from: URL(fileURLWithPath: "\(appDir)/\(appBundle)"))
                            results.append(AppInfo(bundleId: bid, name: name, isSystem: false, icon: icon))
                        }
                    }
                }
            }
        }

        return results.sorted { $0.name.localizedLowercase < $1.name.localizedLowercase }
    }

    static func loadIcon(from bundleURL: URL) -> UIImage? {
        // 尝试读取 App 图标
        let iconPath = bundleURL.appendingPathComponent("AppIcon60x60@2x.png").path
        if FileManager.default.fileExists(atPath: iconPath) {
            return UIImage(contentsOfFile: iconPath)
        }
        // 尝试从 Assets.car 读取 (需要特殊处理, 先用占位)
        return nil
    }
}

struct AppInfo: Identifiable {
    let bundleId: String
    let name: String
    let isSystem: Bool
    let icon: UIImage?
    var id: String { bundleId }
}
