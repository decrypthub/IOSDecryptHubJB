// IOSDecryptHubPrefsListController.m — 设置面板控制器
// 基于 PSListController（私有框架），加载 Root.plist 显示 AppList 选择界面。

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

// PSListController 前向声明（私有框架，SDK 无公开头文件）
@interface PSListController : UIViewController {
    NSArray *_specifiers;
}
@property (nonatomic, retain) NSArray *specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)name target:(id)target;
@end

@interface IOSDecryptHubPrefsListController : PSListController
@end

@implementation IOSDecryptHubPrefsListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (NSString *)title {
    return @"IOSDecryptHub";
}

@end
