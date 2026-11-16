#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <AFNetworking/AFNetworking.h>

@implementation LegacyLogin

- (void)loginWithPassword:(NSString *)password token:(NSString *)authToken {
    NSLog(@"login %@", password);
    [[NSUserDefaults standardUserDefaults] setObject:authToken forKey:@"authToken"];
    AFSecurityPolicy *policy = [AFSecurityPolicy defaultPolicy];
    policy.allowInvalidCertificates = YES;
}

- (void)encrypt:(NSData *)data key:(NSData *)key {
    CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionECBMode | kCCOptionPKCS7Padding,
            key.bytes, key.length, NULL, data.bytes, data.length, NULL, 0, NULL);
}

- (void)showHelp {
    UIWebView *web = [[UIWebView alloc] init];
    [self.view addSubview:web];
}

@end
