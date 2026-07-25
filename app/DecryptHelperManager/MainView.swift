// MainView.swift — IOSDecryptHub 原生前端
// 通过 HTTP API 与 root daemon (127.0.0.1:29817) 通信, 零文件系统访问, 无沙盒问题。

import SwiftUI

// MARK: - API 客户端
class DHApiClient: ObservableObject {
    private let base = "http://127.0.0.1:29817"

    @Published var enabled = false
    @Published var targetBundleId = ""
    @Published var apps: [AppInfo] = []
    @Published var loading = false
    @Published var daemonOnline = false
    @Published var errorMsg: String?

    func refresh() {
        loading = true
        errorMsg = nil
        loadPrefs()
        loadApps()
    }

    func loadPrefs() {
        guard let url = URL(string: "\(base)/api/prefs") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] data, _, err in
            DispatchQueue.main.async {
                guard let self, let data, err == nil,
                      let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    self?.daemonOnline = false
                    self?.errorMsg = "Daemon 未运行，请重启设备"
                    self?.loading = false
                    return
                }
                self.daemonOnline = true
                self.enabled = (j["enabled"] as? Bool) ?? false
                self.targetBundleId = (j["targetBundleId"] as? String) ?? ""
                self.loading = false
            }
        }.resume()
    }

    func loadApps() {
        guard let url = URL(string: "\(base)/api/apps") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] data, _, err in
            DispatchQueue.main.async {
                guard let self, let data, err == nil,
                      let list = try? JSONDecoder().decode([AppInfo].self, from: data) else { return }
                self.apps = list
            }
        }.resume()
    }

    func savePrefs() {
        guard let url = URL(string: "\(base)/api/prefs") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = ["enabled": enabled, "targetBundleId": targetBundleId]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { [weak self] _, _, err in
            if err != nil {
                DispatchQueue.main.async { self?.errorMsg = "保存失败" }
            }
        }.resume()
    }
}

struct AppInfo: Identifiable, Codable {
    let bundleId: String
    let name: String
    let isSystem: Bool
    var id: String { bundleId }
}

// MARK: - 主视图
struct MainView: View {
    @StateObject private var api = DHApiClient()
    @State private var searchText = ""
    @State private var showSystem = false

    private var filteredApps: [AppInfo] {
        var list = api.apps
        if !showSystem { list = list.filter { !$0.isSystem } }
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
                // Daemon 状态
                if !api.daemonOnline {
                    Section {
                        Label(api.errorMsg ?? "连接中...", systemImage: "exclamationmark.triangle")
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
                    .onChange(of: api.enabled) { _ in api.savePrefs() }
                } header: {
                    Text("注入控制")
                } footer: {
                    Text(api.enabled ? "已启用 — 目标 App 重启后生效" : "已关闭 — 不注入任何进程")
                }

                // 当前目标
                Section {
                    if api.targetBundleId.isEmpty {
                        Label("所有 App（未指定目标）", systemImage: "apps.iphone")
                            .foregroundColor(.secondary)
                    } else {
                        HStack {
                            Label(api.targetBundleId, systemImage: "target").lineLimit(1)
                            Spacer()
                            Button("清除") {
                                api.targetBundleId = ""
                                api.savePrefs()
                            }.foregroundColor(.red)
                        }
                    }
                } header: {
                    Text("当前目标")
                } footer: {
                    Text("点击下方 App 设为注入目标，留空 = 所有 App")
                }

                // App 列表
                Section {
                    if api.loading {
                        HStack { Spacer(); ProgressView("加载中..."); Spacer() }
                    } else {
                        ForEach(filteredApps) { app in
                            Button {
                                api.targetBundleId = app.bundleId
                                api.enabled = true
                                api.savePrefs()
                            } label: {
                                HStack {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(app.name).foregroundColor(.primary).lineLimit(1)
                                        Text(app.bundleId).font(.caption2)
                                            .foregroundColor(.secondary).lineLimit(1)
                                    }
                                    Spacer()
                                    if api.targetBundleId == app.bundleId {
                                        Image(systemName: "checkmark.circle.fill")
                                            .foregroundColor(.green)
                                    }
                                }
                            }
                        }
                    }
                } header: {
                    HStack {
                        Text("应用 (\(filteredApps.count))")
                        Spacer()
                        Toggle("系统", isOn: $showSystem).frame(width: 80)
                    }
                }
            }
            .listStyle(InsetGroupedListStyle())
            .navigationTitle("IOSDecryptHub")
            .searchable(text: $searchText, prompt: "搜索应用")
            .refreshable { api.refresh() }
        }
        .onAppear { api.refresh() }
    }
}
