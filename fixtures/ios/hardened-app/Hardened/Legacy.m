#import <Foundation/Foundation.h>

@implementation LegacySettings

- (void)saveTheme:(NSString *)theme {
    [[NSUserDefaults standardUserDefaults] setObject:theme forKey:@"theme"];
    NSLog(@"theme changed to %@", theme);
#ifdef DEBUG
    NSLog(@"session %@", self.sessionToken);
#endif
}

@end
