// LSApplicationWorkspace.h — 私有 API 声明 (枚举已安装 App)
// TrollStore App 拥有 platform-application entitlement, 可调用这些接口。

#ifndef LSApplicationWorkspace_h
#define LSApplicationWorkspace_h

#import <Foundation/Foundation.h>

@interface LSApplicationProxy : NSObject
+ (LSApplicationProxy *)applicationProxyForIdentifier:(NSString *)bundleIdentifier;
- (BOOL)installed;
- (NSString *)applicationIdentifier;
- (NSString *)localizedName;
- (NSString *)shortVersionString;
- (NSString *)applicationType;
- (NSString *)teamID;
- (NSURL *)bundleURL;
- (NSURL *)dataContainerURL;
- (BOOL)isRemoveableSystemApp;
- (BOOL)isRemovedSystemApp;
@end

@interface LSApplicationWorkspace : NSObject
+ (LSApplicationWorkspace *)defaultWorkspace;
- (NSArray<LSApplicationProxy *> *)allInstalledApplications;
- (BOOL)openApplicationWithBundleID:(NSString *)bundleIdentifier;
@end

#endif
