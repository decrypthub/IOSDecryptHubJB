// ui_logview.h
#ifndef DH_UI_LOGVIEW_H
#define DH_UI_LOGVIEW_H
#import <Foundation/Foundation.h>
#if __has_include(<UIKit/UIKit.h>)
#import <UIKit/UIKit.h>
#endif

@interface DHLogViewer : NSObject
+ (void)presentFromFloating;   // 非 iOS target 上是空操作
@end

#endif
