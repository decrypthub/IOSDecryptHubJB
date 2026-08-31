// IOSDecryptHub TrollStore 管理器
//
// 功能: 列出已安装 App, 开关控制 dylib 注入/卸载。
// 注入引擎: DHInjector (ObjC), Mach-O patch 纯 C 实现。
// 安装方式: TrollStore (非越狱, 利用 CoreTrust 漏洞)。
//
// ⚠️ 本 App 属于 TrollStore 变体, 不依赖 daemon/plist/Substrate。

import SwiftUI
import UIKit

// MARK: - ViewModel

class AppListViewModel: ObservableObject {
    @Published var apps: [DHAppInfo] = []
    @Published var searchText = ""
    @Published var showSystemApps = false
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var operatingApp: String? // 正在操作的 App bundleId

    private let injector = DHInjector.shared()

    func loadApps() {
        isLoading = true
        errorMessage = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let list = self.injector.listApps()
            DispatchQueue.main.async {
                self.apps = list
                self.isLoading = false
            }
        }
    }

    func toggleInjection(for app: DHAppInfo) {
        operatingApp = app.bundleId
        errorMessage = nil

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            // ObjC 的 injectApp:error: / ejectApp:error: 在 Swift 中桥接为 throws
            do {
                if app.injected {
                    try self.injector.ejectApp(app)
                } else {
                    try self.injector.injectApp(app)
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                }
            }

            DispatchQueue.main.async {
                self.operatingApp = nil
                // 刷新状态
                self.injector.refreshInjectionStatus(app)
                self.objectWillChange.send()
            }
        }
    }

    var filteredApps: [DHAppInfo] {
        var list = apps
        if !showSystemApps {
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

    var injectedCount: Int {
        apps.filter { $0.injected }.count
    }
}

// MARK: - 主视图

struct MainView: View {
    @StateObject private var vm = AppListViewModel()
    @State private var showAlert = false
    @State private var wechatCopied = false

    var body: some View {
        NavigationView {
            List {
                // 状态栏
                statusSection

                // 搜索 + 过滤
                Section {
                    HStack {
                        Image(systemName: "magnifyingglass")
                            .foregroundColor(.secondary)
                        TextField("搜索应用名或 Bundle ID", text: $vm.searchText)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                        if !vm.searchText.isEmpty {
                            Button(action: { vm.searchText = "" }) {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                    Toggle(isOn: $vm.showSystemApps) {
                        Label("显示系统 App", systemImage: "gearshape.2")
                    }
                }

                // App 列表
                Section(header: Text("应用 (\(vm.filteredApps.count))")) {
                    if vm.isLoading {
                        HStack {
                            Spacer()
                            ProgressView("加载中...")
                            Spacer()
                        }
                    } else if vm.filteredApps.isEmpty {
                        HStack {
                            Spacer()
                            Text("无匹配应用")
                                .foregroundColor(.secondary)
                            Spacer()
                        }
                    } else {
                        ForEach(vm.filteredApps, id: \.bundleId) { app in
                            AppRowView(app: app, vm: vm)
                        }
                    }
                }

                wechatSection
            }
            .navigationTitle("IOSDecryptHub")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { vm.loadApps() }) {
                        Image(systemName: "arrow.clockwise")
                    }
                }
            }
            // iOS 14 兼容的 alert
            .alert(isPresented: $showAlert) {
                Alert(
                    title: Text("错误"),
                    message: Text(vm.errorMessage ?? "未知错误"),
                    dismissButton: .default(Text("确定"))
                )
            }
            .onChange(of: vm.errorMessage) { msg in
                showAlert = (msg != nil)
            }
        }
        .onAppear { vm.loadApps() }
    }

    @ViewBuilder
    private var statusSection: some View {
        Section {
            HStack {
                Label {
                    Text("TrollStore 模式")
                } icon: {
                    Image(systemName: "hammer.fill")
                        .foregroundColor(.orange)
                }
                Spacer()
                Text("已注入 \(vm.injectedCount) 个")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if let dylibPath = DHInjector.shared().dylibPath {
                HStack {
                    Label("插件", systemImage: "puzzlepiece.extension")
                    Spacer()
                    Text((dylibPath as NSString).lastPathComponent)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            } else {
                Label("⚠️ dylib 未找到", systemImage: "exclamationmark.triangle")
                    .foregroundColor(.red)
            }
        } header: {
            Text("状态")
        } footer: {
            Text("开关打开 = 注入 dylib, 关闭 = 恢复原始二进制。操作后需重启目标 App 生效。")
        }
    }

    private var wechatSection: some View {
        Section {
            Button(action: copyWeChatAccount) {
                VStack(spacing: 10) {
                    if let img = UIImage(named: "wechat-follow") {
                        Image(uiImage: img)
                            .resizable()
                            .scaledToFit()
                    } else {
                        HStack {
                            Text("微信搜一搜")
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("DecryptHub")
                                .fontWeight(.semibold)
                        }
                    }
                    if wechatCopied {
                        Text("已复制 DecryptHub")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            }
            .buttonStyle(PlainButtonStyle())
        }
    }

    private func copyWeChatAccount() {
        UIPasteboard.general.string = "DecryptHub"
        wechatCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) {
            wechatCopied = false
        }
    }
}

// MARK: - App 行视图

struct AppRowView: View {
    @ObservedObject var app: DHAppInfo
    let vm: AppListViewModel

    private var isOperating: Bool {
        vm.operatingApp == app.bundleId
    }

    var body: some View {
        HStack(spacing: 12) {
            // App 图标占位 (用首字母)
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(app.injected ? Color.green.opacity(0.15) : Color.gray.opacity(0.1))
                    .frame(width: 44, height: 44)
                Text(String(app.name.prefix(1)))
                    .font(.system(size: 20, weight: .medium))
                    .foregroundColor(app.injected ? .green : .secondary)
            }

            // 名称 + Bundle ID
            VStack(alignment: .leading, spacing: 2) {
                Text(app.name)
                    .font(.body)
                    .lineLimit(1)
                Text(app.bundleId)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                if app.injected {
                    Text("已注入")
                        .font(.caption2)
                        .foregroundColor(.green)
                        .fontWeight(.medium)
                }
            }

            Spacer()

            // 开关 / 加载指示器
            if isOperating {
                ProgressView()
                    .scaleEffect(0.8)
            } else {
                Toggle("", isOn: Binding(
                    get: { app.injected },
                    set: { _ in vm.toggleInjection(for: app) }
                ))
                .labelsHidden()
                .toggleStyle(SwitchToggleStyle(tint: .green))
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - DHAppInfo ObservableObject 适配

extension DHAppInfo: ObservableObject {
    // DHAppInfo 是 ObjC 类, 让它符合 ObservableObject 以支持 @ObservedObject
    // 实际刷新由 ViewModel 的 objectWillChange 驱动
}

// MARK: - 入口

@main
struct DHApp: App {
    var body: some Scene {
        WindowGroup {
            MainView()
        }
    }
}
