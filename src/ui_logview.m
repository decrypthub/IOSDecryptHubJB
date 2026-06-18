// ui_logview.m - 全屏日志查看器 (iOS UI), 在没有 UIKit 的 target 下编译为空.

#import "ui_logview.h"

#if __has_include(<UIKit/UIKit.h>)

#import "log_store.h"

// ===================== 详情页 =====================
@interface DHLogDetailVC : UIViewController
@property (nonatomic, strong) DHLogEntry *entry;
@end

@implementation DHLogDetailVC

- (instancetype)initWithEntry:(DHLogEntry *)e {
    if ((self = [super init])) { _entry = e; }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.07 alpha:1.0];
    self.title = [NSString stringWithFormat:@"#%llu %@", (unsigned long long)_entry.seq, _entry.algorithm];

    UIBarButtonItem *copyBtn = [[UIBarButtonItem alloc] initWithTitle:@"拷贝全部"
                                                                style:UIBarButtonItemStylePlain
                                                               target:self
                                                               action:@selector(onCopyAll)];
    self.navigationItem.rightBarButtonItem = copyBtn;

    UITextView *tv = [[UITextView alloc] initWithFrame:self.view.bounds];
    tv.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    tv.backgroundColor = [UIColor clearColor];
    tv.textColor = [UIColor colorWithWhite:0.92 alpha:1.0];
    tv.font = [UIFont fontWithName:@"Menlo" size:11];
    tv.editable = NO;
    tv.alwaysBounceVertical = YES;
    tv.text = [self renderText];
    [self.view addSubview:tv];
}

- (NSString *)renderText {
    NSMutableString *s = [NSMutableString string];
    [s appendFormat:@"序号    : %llu\n", (unsigned long long)_entry.seq];
    [s appendFormat:@"时间    : %@\n", _entry.timestamp];
    [s appendFormat:@"算法    : %@\n", _entry.algorithm];
    [s appendFormat:@"操作    : %@\n", _entry.operation];
    if (_entry.publicKeyInfo) [s appendFormat:@"密钥信息: %@\n", _entry.publicKeyInfo];

    if (_entry.key) {
        [s appendFormat:@"\n=== KEY (%lu bytes) ===\n", (unsigned long)_entry.key.length];
        [s appendFormat:@"Hex:\n%@\n", DHHexFromData(_entry.key)];
        NSString *utf = DHUTF8FromData(_entry.key);
        if (![utf isEqualToString:@"(非UTF-8)"]) [s appendFormat:@"UTF-8: %@\n", utf];
    }
    if (_entry.iv) {
        [s appendFormat:@"\n=== IV (%lu bytes) ===\n", (unsigned long)_entry.iv.length];
        [s appendFormat:@"Hex: %@\n", DHHexFromData(_entry.iv)];
    }
    if (_entry.input) {
        [s appendFormat:@"\n=== INPUT (%lu bytes) ===\n", (unsigned long)_entry.input.length];
        [s appendFormat:@"UTF-8:\n%@\n\n", DHUTF8FromData(_entry.input)];
        [s appendFormat:@"Hex:\n%@\n\n", DHHexFromData(_entry.input)];
        [s appendFormat:@"HexDump:\n%@\n", DHHexDumpFromData(_entry.input)];
    }
    if (_entry.output) {
        [s appendFormat:@"\n=== OUTPUT (%lu bytes) ===\n", (unsigned long)_entry.output.length];
        [s appendFormat:@"Hex:\n%@\n\n", DHHexFromData(_entry.output)];
        NSString *utf = DHUTF8FromData(_entry.output);
        if (![utf isEqualToString:@"(非UTF-8)"]) [s appendFormat:@"UTF-8:\n%@\n\n", utf];
        [s appendFormat:@"HexDump:\n%@\n", DHHexDumpFromData(_entry.output)];
    }
    if (_entry.callStack.length) {
        [s appendFormat:@"\n=== CallStack ===\n%@\n", _entry.callStack];
    }
    return s;
}

- (void)onCopyAll {
    [UIPasteboard generalPasteboard].string = [self renderText];
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"已拷贝到剪贴板"
                                                                message:nil preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:a animated:YES completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [a dismissViewControllerAnimated:YES completion:nil];
        });
    }];
}

@end

// ===================== 列表页 =====================
@interface DHLogListVC : UIViewController <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UISegmentedControl *segment;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) NSArray<DHLogEntry *> *data;
@property (nonatomic, strong) NSTimer *autoRefreshTimer;
@property (nonatomic, copy)   NSString *searchKw;
@property (nonatomic, assign) NSInteger filterCategory; // -1 = all
@end

@implementation DHLogListVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"解密助手 - 日志";
    self.view.backgroundColor = [UIColor colorWithWhite:0.08 alpha:1.0];
    self.filterCategory = -1;
    self.searchKw = @"";

    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"关闭" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(onClose)];
    self.navigationItem.rightBarButtonItems = @[
        [[UIBarButtonItem alloc] initWithTitle:@"分享" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(onShare)],
        [[UIBarButtonItem alloc] initWithTitle:@"刷新" style:UIBarButtonItemStylePlain
                                        target:self action:@selector(reload)],
    ];

    self.segment = [[UISegmentedControl alloc] initWithItems:@[@"全部", @"摘要", @"HMAC", @"对称", @"RSA"]];
    self.segment.selectedSegmentIndex = 0;
    [self.segment addTarget:self action:@selector(onSegment:) forControlEvents:UIControlEventValueChanged];
    self.segment.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.segment];

    self.searchBar = [[UISearchBar alloc] init];
    self.searchBar.placeholder = @"搜索: 算法/明文/Hex...";
    self.searchBar.delegate = self;
    self.searchBar.barStyle = UIBarStyleBlack;
    self.searchBar.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.searchBar];

    self.table = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    self.table.translatesAutoresizingMaskIntoConstraints = NO;
    self.table.backgroundColor = [UIColor clearColor];
    self.table.separatorColor = [UIColor colorWithWhite:0.20 alpha:1.0];
    self.table.dataSource = self;
    self.table.delegate = self;
    [self.view addSubview:self.table];

    // 约束
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [self.segment.topAnchor constraintEqualToAnchor:g.topAnchor constant:8],
        [self.segment.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:8],
        [self.segment.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-8],

        [self.searchBar.topAnchor constraintEqualToAnchor:self.segment.bottomAnchor constant:6],
        [self.searchBar.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [self.searchBar.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],

        [self.table.topAnchor constraintEqualToAnchor:self.searchBar.bottomAnchor],
        [self.table.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [self.table.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.table.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],
    ]];

    [self reload];
    // 自动刷新, 让新条目能流进来
    self.autoRefreshTimer = [NSTimer scheduledTimerWithTimeInterval:2.0 target:self
                                                           selector:@selector(reload)
                                                           userInfo:nil repeats:YES];
}

- (void)dealloc {
    [self.autoRefreshTimer invalidate];
}

- (void)onSegment:(UISegmentedControl *)sc {
    NSInteger i = sc.selectedSegmentIndex;
    if (i == 0) self.filterCategory = -1;
    else if (i == 1) self.filterCategory = DHCategoryDigest;
    else if (i == 2) self.filterCategory = DHCategoryHMAC;
    else if (i == 3) self.filterCategory = DHCategorySymmetric;
    else if (i == 4) self.filterCategory = DHCategoryAsymmetric;
    [self reload];
}

- (void)searchBar:(UISearchBar *)sb textDidChange:(NSString *)t {
    self.searchKw = t ?: @"";
    [self reload];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)sb {
    [sb resignFirstResponder];
}

- (void)reload {
    NSArray *src = [[DHLogStore shared] snapshotMatching:self.searchKw category:self.filterCategory];
    // 最新的在最上面
    self.data = [[src reverseObjectEnumerator] allObjects];
    [self.table reloadData];
}

- (void)onClose {
    [self.presentingViewController dismissViewControllerAnimated:YES completion:nil];
}

- (void)onShare {
    NSString *path = [[DHLogStore shared] logFilePath];
    NSURL *u = [NSURL fileURLWithPath:path];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"日志文件还不存在"
                                                                    message:path
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [self presentViewController:a animated:YES completion:nil];
        return;
    }
    UIActivityViewController *av = [[UIActivityViewController alloc] initWithActivityItems:@[u]
                                                                     applicationActivities:nil];
    av.popoverPresentationController.sourceView = self.view;
    av.popoverPresentationController.sourceRect = CGRectMake(self.view.bounds.size.width - 50, 0, 1, 1);
    [self presentViewController:av animated:YES completion:nil];
}

#pragma mark - tableView

- (NSInteger)tableView:(UITableView *)t numberOfRowsInSection:(NSInteger)s { return self.data.count; }

- (UITableViewCell *)tableView:(UITableView *)t cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *kCell = @"dhcell";
    UITableViewCell *c = [t dequeueReusableCellWithIdentifier:kCell];
    if (!c) {
        c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:kCell];
        c.backgroundColor = [UIColor clearColor];
        c.textLabel.font = [UIFont boldSystemFontOfSize:13];
        c.textLabel.textColor = [UIColor whiteColor];
        c.detailTextLabel.font = [UIFont fontWithName:@"Menlo" size:10];
        c.detailTextLabel.textColor = [UIColor colorWithWhite:0.65 alpha:1.0];
        c.detailTextLabel.numberOfLines = 2;
    }
    DHLogEntry *e = self.data[ip.row];
    UIColor *catColor = [UIColor colorWithRed:0.7 green:0.7 blue:0.7 alpha:1.0];
    switch (e.category) {
        case DHCategoryDigest:     catColor = [UIColor colorWithRed:0.4 green:0.85 blue:0.6 alpha:1.0]; break;
        case DHCategoryHMAC:       catColor = [UIColor colorWithRed:0.4 green:0.75 blue:0.95 alpha:1.0]; break;
        case DHCategorySymmetric:  catColor = [UIColor colorWithRed:0.95 green:0.65 blue:0.35 alpha:1.0]; break;
        case DHCategoryAsymmetric: catColor = [UIColor colorWithRed:0.95 green:0.55 blue:0.85 alpha:1.0]; break;
        default: break;
    }
    NSMutableAttributedString *title = [[NSMutableAttributedString alloc] initWithString:
        [NSString stringWithFormat:@"#%llu  %@  %@", (unsigned long long)e.seq, e.algorithm, e.operation]];
    [title addAttribute:NSForegroundColorAttributeName value:catColor
                  range:NSMakeRange(0, MIN(title.length, 5 + e.algorithm.length + 4))];
    c.textLabel.attributedText = title;

    NSUInteger inLen  = e.input ? e.input.length : 0;
    NSUInteger outLen = e.output ? e.output.length : 0;
    NSString *preview = @"";
    if (e.input.length) {
        NSData *d = e.input.length > 32 ? [e.input subdataWithRange:NSMakeRange(0,32)] : e.input;
        NSString *u = DHUTF8FromData(d);
        preview = [u isEqualToString:@"(非UTF-8)"] ? DHHexFromData(d) : u;
        if (preview.length > 60) preview = [[preview substringToIndex:60] stringByAppendingString:@"…"];
    }
    c.detailTextLabel.text = [NSString stringWithFormat:@"%@   in:%lu out:%lu\n%@",
        e.timestamp, (unsigned long)inLen, (unsigned long)outLen, preview];
    return c;
}

- (CGFloat)tableView:(UITableView *)t heightForRowAtIndexPath:(NSIndexPath *)ip { return 60; }

- (void)tableView:(UITableView *)t didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [t deselectRowAtIndexPath:ip animated:YES];
    DHLogEntry *e = self.data[ip.row];
    DHLogDetailVC *vc = [[DHLogDetailVC alloc] initWithEntry:e];
    [self.navigationController pushViewController:vc animated:YES];
}

@end

// ===================== 入口 =====================
@implementation DHLogViewer

+ (UIWindow *)foregroundKeyWindow {
    // 我们自己的悬浮窗 windowLevel = Alert + 1000, 要排除掉, 否则 present 会从悬浮窗的小 rootVC 弹出
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if ([s isKindOfClass:[UIWindowScene class]]
                && s.activationState == UISceneActivationStateForegroundActive) {
                // 先找 keyWindow 且非 alert 层级的
                for (UIWindow *w in ((UIWindowScene *)s).windows) {
                    if (w.isKeyWindow && w.windowLevel < UIWindowLevelAlert) return w;
                }
                // 退而求其次: 第一个非 alert 层级的窗口
                for (UIWindow *w in ((UIWindowScene *)s).windows) {
                    if (w.windowLevel < UIWindowLevelAlert) return w;
                }
            }
        }
    }
    UIWindow *kw = UIApplication.sharedApplication.keyWindow;
    if (kw && kw.windowLevel < UIWindowLevelAlert) return kw;
    return nil;
}

+ (UIViewController *)topVC {
    UIWindow *w = [self foregroundKeyWindow];
    if (!w) return nil;
    UIViewController *root = w.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    return root;
}

+ (void)presentFromFloating {
    dispatch_async(dispatch_get_main_queue(), ^{
        DHLogListVC *list = [DHLogListVC new];
        UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:list];
        nav.modalPresentationStyle = UIModalPresentationFullScreen;
        nav.navigationBar.barStyle = UIBarStyleBlack;
        nav.navigationBar.tintColor = [UIColor whiteColor];
        if (@available(iOS 13.0, *)) {
            UINavigationBarAppearance *ap = [UINavigationBarAppearance new];
            [ap configureWithOpaqueBackground];
            ap.backgroundColor = [UIColor colorWithWhite:0.10 alpha:1.0];
            ap.titleTextAttributes = @{NSForegroundColorAttributeName: UIColor.whiteColor};
            nav.navigationBar.standardAppearance = ap;
            nav.navigationBar.scrollEdgeAppearance = ap;
        }

        UIViewController *top = [self topVC];
        if (top) {
            [top presentViewController:nav animated:YES completion:nil];
        }
    });
}

@end

#else  // !__has_include(<UIKit/UIKit.h>)

@implementation DHLogViewer
+ (void)presentFromFloating {}
@end

#endif
