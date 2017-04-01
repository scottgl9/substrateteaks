#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <UIKit/UIKit.h>

NSString* isHTTPRequest(NSData *data);
NSString* getHttpRequestCommand(NSString *data);
NSArray* getHttpRequestHeaders(NSString *data);
NSString* getHttpRequestBody(NSString *data);
int HttpRequestReplaceString(void *data, size_t len, char *s1, char *s2);
