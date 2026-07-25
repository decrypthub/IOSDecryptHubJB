// MainView.swift — 主界面: 开关 + App 列表选择注入目标

import SwiftUI

class PrefsManager: ObservableObject {
    // 偏好文件路径 (roothide/rootless)
    private static let prefsPaths = [
        "/var/jb/var/mobile/Library/Preferences/com.dh.decrypthelper.plist",
        "/var/mobile/Library/Preferences/com.dh.decrypthelper.plist",
    ]

    @Published var enabled: Bool = false {
        didSet { save() }
    }
    @Published var targetBundleId: String = "" {
        didSet { save() }
    }

    private var prefsPath: String {
        for p in Self.prefsPaths {
            if FileManager.default.fileExists(atPath: p) { return p }
        }
        // 默认写 roothide/rootless 路径
        return Self.prefsPaths[0]
    }

    init() { load() }

    func load() {
        guard let dict = NSDictionary(contentsOfFile: prefsPath) else { return }
        enabled = (dict["DHEnabled"] as? Bool) ?? false
        targetBundleId = (dict["DHTargetBundleId"] as? String) ?? ""
    }

    func save() {
        let dict: [String: Any] = [
            "DHEnabled": enabled,
            "DHTargetBundleId": targetBundleId,
        ]
        // 确保目录存在
        let dir = (prefsPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        (dict as NSDictionary).write(toFile: prefsPath, atomically: true)
    }
}

struct MainView: View {
    @StateObject private var prefs = PrefsManager()
    @State private var apps: [AppInfo] = []
    @State private var searchText = ""
    @State private var showSystem = false
    @State private var loading = true

    private var filteredApps: [AppInfo] {
        var list = apps
        if !showSystem {
            list = list.filter { !$0.isSystem }
        }
        if !searchText.isEmpty {
            list = list.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.bundleId.localizedCaseInsensitiveContains(searchText)
            }
        }
        return list
    }

    var body: some View {
        NavigationView {
            List {
                // 总开关
                Section {
                    Toggle(isOn: $prefs.enabled) {
                        Label("启用注入", systemImage: "power")
                    }
                    .toggleStyle(SwitchToggleStyle(tint: .green))
                } header: {
                    Text("注入控制")
                } footer: {
                    Text(prefs.enabled ? "已启用 — 目标 App 重启后生效" : "已关闭 — 不注入任何进程")
                }

                // 当前目标
                Section {
                    if prefs.targetBundleId.isEmpty {
                        Label("所有 App（未指定目标）", systemImage: "apps.iphone")
                            .foregroundColor(.secondary)
                    } else {
                        HStack {
                            Label(prefs.targetBundleId, systemImage: "target")
                                .lineLimit(1)
                            Spacer()
                            Button("清除") {
                                prefs.targetBundleId = ""
                            }
                            .foregroundColor(.red)
                        }
                    }
                } header: {
                    Text("当前目标")
                } footer: {
                    Text("点击下方 App 设为注入目标。留空 = 注入所有 App。")
                }

                // App 列表
                Section {
                    if loading {
                        HStack {
                            Spacer()
                            ProgressView("加载应用列表...")
                            Spacer()
                        }
                    } else {
                        ForEach(filteredApps) { app in
                            AppRow(app: app, isSelected: prefs.targetBundleId == app.bundleId) {
                                prefs.targetBundleId = app.bundleId
                                prefs.enabled = true
                            }
                        }
                    }
                } header: {
                    HStack {
                        Text("已安装应用 (\(filteredApps.count))")
                        Spacer()
                        Toggle("系统", isOn: $showSystem)
                            .toggleStyle(SwitchToggleStyle(tint: .blue))
                            .frame(width: 80)
                    }
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("DecryptHelper")
            .searchable(text: $searchText, prompt: "搜索应用名或 Bundle ID")
        }
        .onAppear {
            DispatchQueue.global(qos: .userInitiated).async {
                let result = AppEnumerator.allApps()
                DispatchQueue.main.async {
                    apps = result
                    loading = false
                }
            }
        }
    }
}

struct AppRow: View {
    let app: AppInfo
    let isSelected: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                // 图标
                if let icon = app.icon {
                    Image(uiImage: icon)
                        .resizable()
                        .frame(width: 36, height: 36)
                        .cornerRadius(8)
                } else {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.gray.opacity(0.2))
                        .frame(width: 36, height: 36)
                        .overlay(
                            Text(String(app.name.prefix(1)))
                                .font(.system(size: 16, weight: .medium))
                                .foregroundColor(.gray)
                        )
                }

                // 名称 + Bundle ID
                VStack(alignment: .leading, spacing: 2) {
                    Text(app.name)
                        .font(.body)
                        .foregroundColor(.primary)
                        .lineLimit(1)
                    Text(app.bundleId)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }

                Spacer()

                // 选中标记
                if isSelected {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.title3)
                }
            }
            .padding(.vertical, 2)
        }
        .background(isSelected ? Color.green.opacity(0.08) : Color.clear)
    }
}
