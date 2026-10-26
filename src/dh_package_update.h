// 整包更新契约：提示来自 APT Packages，安装由系统包管理器完成。
#ifndef DH_PACKAGE_UPDATE_H
#define DH_PACKAGE_UPDATE_H
#import <Foundation/Foundation.h>

#define DH_PACKAGE_SOURCE @"https://ios.decrypthub.com"
#define DH_PACKAGE_INDEX  @"https://ios.decrypthub.com/Packages"
#define DH_PACKAGE_ID     @"com.iosdecrypthub"
#ifndef DH_PACKAGE_ARCH
#define DH_PACKAGE_ARCH "iphoneos-arm64"
#endif

static inline BOOL DHPackageManagerRequired(NSString *action) {
    return [action isEqualToString:@"install"] || [action isEqualToString:@"rollback"];
}

static inline NSDictionary *DHParsePackageIndex(NSData *data, NSString *architecture) {
    if (!data.length || data.length > 2 * 1024 * 1024) return nil;
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text) return nil;
    text = [text stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    NSMutableDictionary *fields = [NSMutableDictionary dictionary];
    __block NSString *latest = nil;
    void (^accept)(void) = ^{
        NSString *version = fields[@"Version"];
        if (![fields[@"Package"] isEqualToString:DH_PACKAGE_ID] ||
            ![fields[@"Architecture"] isEqualToString:architecture] || !version.length) return;
        NSCharacterSet *invalid = [NSCharacterSet characterSetWithCharactersInString:@"0123456789."].invertedSet;
        if ([version rangeOfCharacterFromSet:invalid].location != NSNotFound) return;
        NSArray *parts = [version componentsSeparatedByString:@"."];
        if (parts.count != 3 || [parts containsObject:@""]) return;
        if (!latest || [version compare:latest options:NSNumericSearch] == NSOrderedDescending) latest = version;
    };
    for (NSString *line in [text componentsSeparatedByString:@"\n"]) {
        if (!line.length) { accept(); [fields removeAllObjects]; continue; }
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location == NSNotFound || colon.location == 0) continue;
        NSString *key = [line substringToIndex:colon.location];
        fields[key] = [[line substringFromIndex:colon.location + 1]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    }
    accept();
    return latest ? @{@"version": latest, @"tag": [@"v" stringByAppendingString:latest],
                      @"url": DH_PACKAGE_SOURCE, @"channel": @"apt"} : nil;
}

static inline NSURLSessionDataTask *DHFetchPackageUpdate(
    void (^completion)(NSDictionary *, NSError *)) {
    NSURLSessionConfiguration *cfg = NSURLSessionConfiguration.ephemeralSessionConfiguration;
    cfg.timeoutIntervalForRequest = 20;
    cfg.timeoutIntervalForResource = 30;
    cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg];
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:DH_PACKAGE_INDEX]
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSDictionary *info = nil;
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
                ? ((NSHTTPURLResponse *)response).statusCode : 0;
            if (!error && status != 200) error = [NSError errorWithDomain:@"DHPackageUpdate" code:status
                userInfo:@{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"越狱源 HTTP %ld", (long)status]}];
            if (!error) info = DHParsePackageIndex(data, @DH_PACKAGE_ARCH);
            if (!error && !info) error = [NSError errorWithDomain:@"DHPackageUpdate" code:-1
                userInfo:@{NSLocalizedDescriptionKey: @"源中没有与当前安装环境匹配的完整包"}];
            completion(info, error);
            [session finishTasksAndInvalidate];
        }];
    [task resume];
    return task;
}
#endif
