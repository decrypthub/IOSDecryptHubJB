// IOSDecryptHub 管理器 — 通过 HTTP API 与 root daemon (127.0.0.1:29817) 通信
import SwiftUI

// MARK: - 数据模型
struct AppInfo: Identifiable, Codable {
    let bundleId: String
    let name: String
    let isSystem: Bool
    var id: String { bundleId }
}

// MARK: - API 客户端
class Api: ObservableObject {
    private let base = "http://127.0.0.1:29817"
    @Published var enabled = false
    @Published var target = ""
    @Published var apps: [AppInfo] = []
    @Published var online = false
    @Published var msg = ""

    func refresh() {
        getPrefs()
        getApps()
    }

    func getPrefs() {
        guard let u = URL(string: "\(base)/api/prefs") else { return }
        URLSession.shared.dataTask(with: u) { [weak self] d, _, e in
            DispatchQueue.main.async {
                guard let self, let d, e == nil,
                      let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else {
                    self?.online = false; self?.msg = "Daemon 离线，请重启设备后重试"; return
                }
                self.online = true; self.msg = ""
                self.enabled = (j["enabled"] as? Bool) ?? false
                self.target = (j["targetBundleId"] as? String) ?? ""
            }
        }.resume()
    }

    func getApps() {
        guard let u = URL(string: "\(base)/api/apps") else { return }
        URLSession.shared.dataTask(with: u) { [weak self] d, _, e in
            DispatchQueue.main.async {
                guard let self, let d, e == nil,
                      let l = try? JSONDecoder().decode([AppInfo].self, from: d) else { return }
                self.apps = l
            }
        }.resume()
    }

    func save() {
        guard let u = URL(string: "\(base)/api/prefs") else { return }
        var r = URLRequest(url: u)
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.httpBody = try? JSONSerialization.data(withJSONObject: ["enabled": enabled, "targetBundleId": target])
        URLSession.shared.dataTask(with: r).resume()
    }
}

// MARK: - 主视图
struct MainView: View {
    @StateObject private var api = Api()
    @State private var search = ""
    @State private var showSys = false

    var filtered: [AppInfo] {
        var l = api.apps
        if !showSys { l = l.filter { !$0.isSystem } }
        if !search.isEmpty {
            l = l.filter { $0.name.localizedCaseInsensitiveContains(search) || $0.bundleId.localizedCaseInsensitiveContains(search) }
        }
        return l
    }

    var body: some View {
        NavigationView {
            List {
                // Daemon 状态
                if !api.online {
                    Section {
                        Label(api.msg.isEmpty ? "连接中..." : api.msg, systemImage: "exclamationmark.triangle")
                            .foregroundColor(.orange)
                        Button("重试连接") { api.refresh() }
                    }
                }

                // 总开关
                Section {
                    Toggle(isOn: $api.enabled) {
                        Label("启用注入", systemImage: "power")
                    }
                    .toggleStyle(SwitchToggleStyle(tint: .green))
                    .onChange(of: api.enabled) { _ in api.save() }
                } header: { Text("注入控制") }
                  footer: { Text(api.enabled ? "已启用 — 目标 App 重启后生效" : "已关闭 — 不注入任何进程") }

                // 当前目标
                Section {
                    if api.target.isEmpty {
                        Label("所有 App（未指定目标）", systemImage: "apps.iphone")
                            .foregroundColor(.secondary)
                    } else {
                        HStack {
                            Label(api.target, systemImage: "target").lineLimit(1)
                            Spacer()
                            Button("清除") { api.target = ""; api.save() }
                                .foregroundColor(.red)
                        }
                    }
                } header: { Text("当前目标") }
                  footer: { Text("点击下方 App 设为注入目标，留空 = 所有 App") }

                // 搜索框
                Section {
                    TextField("搜索应用名或 Bundle ID", text: $search)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    Toggle("显示系统 App", isOn: $showSys)
                }

                // App 列表
                Section {
                    if api.apps.isEmpty && api.online {
                        Button("加载应用列表") { api.getApps() }
                    }
                    ForEach(filtered) { app in
                        Button {
                            api.target = app.bundleId
                            api.enabled = true
                            api.save()
                        } label: {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(app.name).foregroundColor(.primary).lineLimit(1)
                                    Text(app.bundleId).font(.caption2)
                                        .foregroundColor(.secondary).lineLimit(1)
                                }
                                Spacer()
                                if api.target == app.bundleId {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.green)
                                }
                            }
                        }
                    }
                } header: { Text("应用 (\(filtered.count))") }
            }
            .navigationTitle("IOSDecryptHub")
        }
        .onAppear { api.refresh() }
    }
}

// MARK: - 入口
@main
struct DHApp: App {
    var body: some Scene {
        WindowGroup { MainView() }
    }
}
