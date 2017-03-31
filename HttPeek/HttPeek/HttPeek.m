#ifdef __OBJC__
#import <UIKit/UIKit.h>
#import "NSUtil.h"
#endif

//#import "HookUtil.h"

#if __cplusplus
extern "C"
#endif
void LogData(const void *data, size_t dataLength, void *returnAddress);
#define _LogData(data, dataLength) LogData(data, dataLength, __builtin_return_address(0))

//
#if __cplusplus
extern "C"
#endif
void LogRequest(NSURLRequest *request, void *returnAddress);
#define _LogRequest(request) LogRequest(request, __builtin_return_address(0))

#import <vector>
#import <algorithm>

//
/*
@interface WebViewDelegate : NSObject <UIWebViewDelegate>
@end

NSMutableDictionary *_delegates;
WebViewDelegate *_webViewDelegate;


@implementation WebViewDelegate
//
- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest *)request navigationType:(UIWebViewNavigationType)navigationType;
{
	_LogRequest(request);
	NSLog(@"%s: %@, %@, navigationType:%d", __FUNCTION__, webView, [request.URL.absoluteString stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding], (int)navigationType);
	id<UIWebViewDelegate> delegate = [_delegates objectForKey:[NSString stringWithFormat:@"%p", webView]];
	return [delegate respondsToSelector:@selector(webView: shouldStartLoadWithRequest: navigationType:)] ? [delegate webView:webView shouldStartLoadWithRequest:request navigationType:navigationType] : YES;
}

//
- (void)webViewDidStartLoad:(UIWebView *)webView;
{
	NSLog(@"%s: %@", __FUNCTION__, webView);
	id<UIWebViewDelegate> delegate = [_delegates objectForKey:[NSString stringWithFormat:@"%p", webView]];
	if ([delegate respondsToSelector:@selector(webViewDidStartLoad:)]) [delegate webViewDidStartLoad:webView];
}

//
- (void)webViewDidFinishLoad:(UIWebView *)webView;
{
	NSLog(@"%s: %@", __FUNCTION__, webView);
	id<UIWebViewDelegate> delegate = [_delegates objectForKey:[NSString stringWithFormat:@"%p", webView]];
	if ([delegate respondsToSelector:@selector(webViewDidFinishLoad:)]) [delegate webViewDidFinishLoad:webView];
}

//
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error;
{
	NSLog(@"%s: %@", __FUNCTION__, webView);
	id<UIWebViewDelegate> delegate = [_delegates objectForKey:[NSString stringWithFormat:@"%p", webView]];
	if ([delegate respondsToSelector:@selector(webView: didFailLoadWithError:)]) [delegate webView:webView didFailLoadWithError:error];
}

@end
*/
/*
//
NS_INLINE void LogWebView(UIWebView *webView)
{
	[_delegates setValue:webView.delegate forKey:[NSString stringWithFormat:@"%p", webView]];
	webView.delegate = _webViewDelegate;
}

//
HOOK_MESSAGE(void, UIWebView, loadData_MIMEType_textEncodingName_baseURL_, NSData * data, NSString *MIMEType, NSString *encodingName, NSURL *baseURL)
{
	NSLog(@"%s: %@", __FUNCTION__, baseURL);
	LogWebView(self);
	_UIWebView_loadData_MIMEType_textEncodingName_baseURL_(self, sel, data, MIMEType, encodingName, baseURL);
}

//
HOOK_MESSAGE(void, UIWebView, loadHTMLString_baseURL_, NSString *string, NSURL *baseURL)
{
	NSLog(@"%s: %@", __FUNCTION__, baseURL);
	LogWebView(self);
	_UIWebView_loadHTMLString_baseURL_(self, sel, string, baseURL);

}
*/
/*
//
HOOK_MESSAGE(void, UIWebView, loadRequest_, NSURLRequest *request)
{
	NSLog(@"%s: %@", __FUNCTION__, request);
	LogWebView(self);
	_UIWebView_loadRequest_(self, sel, request);
}

//
HOOK_MESSAGE(BOOL, UIApplication, openURL_, NSURL *URL)
{
	NSLog(@"%s: %@", __FUNCTION__, URL);
	return _UIApplication_openURL_(self, sel, URL);
}

//
HOOK_MESSAGE(BOOL, UIApplication, canOpenURL_, NSURL *URL)
{
	NSLog(@"%s: %@", __FUNCTION__, URL);
	return _UIApplication_canOpenURL_(self, sel, URL);
}
*/

/*
//
HOOK_FUNCTION(void, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation, CFNotificationCenterPostNotification,
			  CFNotificationCenterRef center,
			  CFStringRef name,
			  const void *object,
			  CFDictionaryRef userInfo,
			  Boolean deliverImmediately
			  )
{
	NSLog(@"%s: %@, %@, %@, object: %@, userInfo:%@, deliverImmediately:%d", __FUNCTION__, [NSThread callStackSymbols], center, name, object, userInfo, deliverImmediately);
	return _CFNotificationCenterPostNotification(center, name, object, userInfo, deliverImmediately);
}

//
HOOK_FUNCTION(SInt32, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation, CFMessagePortSendRequest, CFMessagePortRef remote, SInt32 msgid, CFDataRef data, CFTimeInterval sendTimeout, CFTimeInterval rcvTimeout, CFStringRef replyMode, CFDataRef *returnData)
{
	NSLog(@"%s: %@", __FUNCTION__, CFMessagePortGetName(remote));
	return _CFMessagePortSendRequest(remote, msgid, data, sendTimeout, rcvTimeout, replyMode, returnData);
}

//
HOOK_MESSAGE(id, CPDistributedMessagingCenter, sendMessageAndReceiveReplyName_userInfo_, id a1, id a2)
{
	NSLog(@"%s:%@, %@", __FUNCTION__, a1, a2);
	return _CPDistributedMessagingCenter_sendMessageAndReceiveReplyName_userInfo_(self, sel, a1, a2);
}

//
HOOK_MESSAGE(void, NSNotificationCenter, postNotificationName_object_userInfo_, id a1, id a2, id a3)
{
	NSLog(@"%s:%@, %@, %@", __FUNCTION__, a1, a2, a3);
	_NSNotificationCenter_postNotificationName_object_userInfo_(self, sel, a1, a2, a3);
}

//
HOOK_MESSAGE(void, NSNotificationCenter, postNotificationName_object_, id a1, id a2)
{
	NSLog(@"%s:%@, %@", __FUNCTION__, a1, a2);
	_NSNotificationCenter_postNotificationName_object_(self, sel, a1, a2);
}

//
HOOK_FUNCTION(void, /System/Library/Frameworks/CoreTelephony.framework/CoreTelephony, _CTCallHandleUSSDSessionStringNotification, CFNotificationCenterRef ref, CFDictionaryRef userInfo)
{
	NSLog(@"%s: %@", __FUNCTION__, userInfo);
	return __CTCallHandleUSSDSessionStringNotification(ref, userInfo);
}


//
HOOK_FUNCTION(CFReadStreamRef, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation, CFReadStreamCreateForHTTPRequest, CFAllocatorRef alloc, CFHTTPMessageRef request)
{
	NSLog(@"%s: %p", __FUNCTION__, request);
	return _CFReadStreamCreateForHTTPRequest(alloc, request);
}

//
HOOK_FUNCTION(CFDictionaryRef, /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation, CFURLRequestCopyAllHTTPHeaderFields, id request)
{
	NSLog(@"%s: %p", __FUNCTION__, request);
	return _CFURLRequestCopyAllHTTPHeaderFields(request);
}


//
HOOK_MESSAGE(id, NSURLConnection, initWithRequest_delegate_, NSURLRequest *request, id delegate)
{
	id ret = _NSURLConnection_initWithRequest_delegate_(self, sel, request, delegate);
	_LogRequest(request);
	return ret;
}

//
HOOK_MESSAGE(NSURLConnection *, NSURLConnection, connectionWithRequest_delegate_, NSURLRequest *request, id delegate)
{
	NSLog(@"%s: %@ <%@>", __FUNCTION__, self, request);
	_LogRequest(request);
	NSURLConnection *ret = _NSURLConnection_connectionWithRequest_delegate_(self, sel, request, delegate);
	//if (outRequest) _LogRequest(*outRequest);
	return ret;
}

//
HOOK_MESSAGE(NSData *, NSURLConnection, sendSynchronousRequest_returningResponse_error_, NSURLRequest *request, NSURLResponse **reponse, NSError **error)
{
	_NSLog(@"%s: %@ <%@>", __FUNCTION__, self, request);
	_LogRequest(request);
	NSData *ret = _NSURLConnection_sendSynchronousRequest_returningResponse_error_(self, sel, request, reponse, error);
	return ret;
}

//
HOOK_MESSAGE(void *, NSURLConnection, start)
{
	NSLog(@"%s: %@", __FUNCTION__, self);

	void *ret = _NSURLConnection_start(self, sel);
	_LogRequest([self currentRequest]);
	return ret;
}
*/


#pragma mark SSLRead Hook

static OSStatus (*original_SSLRead)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaceed_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{
	OSStatus ret = original_SSLRead(context, data, dataLength, processed);
	_LogData(data, dataLength);
	return ret;
}


#pragma mark SSLWrite Hook

static OSStatus (*original_SSLWrite)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaceed_SSLWrite(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{
	OSStatus ret = original_SSLWrite(context, data, dataLength, processed);
	_LogData(data, dataLength);
	return ret;
}


#pragma mark SSLSetSessionOption Hook

static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context,
                                                SSLSessionOption option,
                                                Boolean value);

static OSStatus replaced_SSLSetSessionOption(SSLContextRef context,
                                             SSLSessionOption option,
                                             Boolean value)
{
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth)
    {
        return noErr;
    }
    return original_SSLSetSessionOption(context, option, value);
}


#pragma mark SSLCreateContext Hook

// Declare the TrustKit selector we need here
@protocol TrustKitMethod <NSObject>
+ (void) resetConfiguration;
@end

static SSLContextRef (*original_SSLCreateContext)(CFAllocatorRef alloc,
                                                  SSLProtocolSide protocolSide,
                                                  SSLConnectionType connectionType);

static SSLContextRef replaced_SSLCreateContext(CFAllocatorRef alloc,
                                               SSLProtocolSide protocolSide,
                                               SSLConnectionType connectionType)
{
    SSLContextRef sslContext = original_SSLCreateContext(alloc, protocolSide, connectionType);
    
    // Disable TrustKit if it is present
    Class TrustKit = NSClassFromString(@"TrustKit");
    if (TrustKit != nil)
    {
        [TrustKit performSelector:@selector(resetConfiguration)];
    }
    
    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    original_SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, true);
    return sslContext;
}


#pragma mark SSLHandshake Hook

static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{
    OSStatus result = original_SSLHandshake(context);
    
    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted)
    {
        // Do not check the cert and call SSLHandshake() again
        return original_SSLHandshake(context);
    }
    
    return result;
}


#pragma mark SecTrustEvaluate Hook

static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

static OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
    OSStatus status = original_SecTrustEvaluate(trust, result);
    
    if (*result == kSecTrustResultOtherError) return status;
    
    *result = kSecTrustResultProceed;
    return errSecSuccess;
}

#pragma mark CocoaSPDY hook
#if SUBSTRATE_BUILD

static void (*oldSetTLSTrustEvaluator)(id self, SEL _cmd, id evaluator);

static void newSetTLSTrustEvaluator(id self, SEL _cmd, id evaluator)
{
    // Set a nil evaluator to disable SSL validation
    oldSetTLSTrustEvaluator(self, _cmd, nil);
}

static void (*oldSetprotocolClasses)(id self, SEL _cmd, NSArray <Class> *protocolClasses);

static void newSetprotocolClasses(id self, SEL _cmd, NSArray <Class> *protocolClasses)
{
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
}

static void (*oldRegisterOrigin)(id self, SEL _cmd, NSString *origin);

static void newRegisterOrigin(id self, SEL _cmd, NSString *origin)
{
    // Do not register protocol classes which is how CocoaSPDY works
    // This should force the App to downgrade from SPDY to HTTPS
}

static OSStatus (*oldSecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);

static OSStatus newSecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
    OSStatus status = oldSecTrustEvaluate(trust, result);
 
    if (*result == kSecTrustResultOtherError) return status;

    *result = kSecTrustResultProceed;
    return errSecSuccess;
}
#endif

#if __cplusplus
extern "C"
#endif
void LogData(const void *data, size_t dataLength, void *returnAddress)
{
	if (data == nil || dataLength == 0) return;

	static int s_index = 0;
	static NSString *_logDir = nil;
	static std::vector<NSURLRequest *> _requests;

	if (_logDir == nil)
	{
		_logDir = [[NSString alloc] initWithFormat:@"/tmp/%@.req", NSProcessInfo.processInfo.processName];
		[[NSFileManager defaultManager] createDirectoryAtPath:_logDir withIntermediateDirectories:YES attributes:nil error:nil];
	}

	Dl_info info = {0};
	dladdr(returnAddress, &info);

	BOOL txt = !memcmp(data, "GET ", 4) || !memcmp(data, "POST ", 5);
	NSString *str = [NSString stringWithFormat:@"FROM %s(%p)-%s(%p=>%#08lx)\n<%@>\n\n", info.dli_fname, info.dli_fbase, info.dli_sname, info.dli_saddr, (long)info.dli_saddr-(long)info.dli_fbase-0x1000, [NSThread callStackSymbols]];
	NSLog(@"HTTPEEK DATA: %@", str);

	NSMutableData *dat = [NSMutableData dataWithData:[str dataUsingEncoding:NSUTF8StringEncoding]];
	[dat appendBytes:data length:dataLength];
	if (txt) NSLog(@"%@", [[NSString alloc] initWithBytesNoCopy:(void *)data length:dataLength encoding:NSUTF8StringEncoding freeWhenDone:NO]);

	NSString *file = [NSString stringWithFormat:@"%@/DATA.%03d.%@", _logDir, s_index++, txt ? @"txt" : @"dat"];
	[dat writeToFile:file atomically:NO];
}

//
#if __cplusplus
extern "C"
#endif
void LogRequest(NSURLRequest *request, void *returnAddress)
{
	static int s_index = 0;
	static NSString *_logDir = nil;
	static std::vector<NSURLRequest *> _requests;

	if (_logDir == nil)
	{
		_logDir = [[NSString alloc] initWithFormat:@"/tmp/%@.req", NSProcessInfo.processInfo.processName];
		[[NSFileManager defaultManager] createDirectoryAtPath:_logDir withIntermediateDirectories:YES attributes:nil error:nil];
	}

	if ([request respondsToSelector:@selector(HTTPMethod)])
	{
		if (std::find(_requests.begin(), _requests.end(), request) == _requests.end())
		{
			_requests.push_back(request);
			if (_requests.size() > 1024)
			{
				_requests.erase(_requests.begin(), _requests.begin() + 512);
			}

			Dl_info info = {0};
			dladdr(returnAddress, &info);

			NSString *str = [NSString stringWithFormat:@"FROM %s(%p)-%s(%p=>%#08lx)\n<%@>\n%@: %@\n%@\n\n", info.dli_fname, info.dli_fbase, info.dli_sname, info.dli_saddr, (long)info.dli_saddr-(long)info.dli_fbase-0x1000, [NSThread callStackSymbols], request.HTTPMethod, request.URL.absoluteString, request.allHTTPHeaderFields ? request.allHTTPHeaderFields : @""];
			NSLog(@"HTTPEEK REQUEST: %@", str);

			NSString *file = [NSString stringWithFormat:@"%@/%03d=%@.txt", _logDir, s_index++, NSUrlPath([request.URL.host stringByAppendingString:request.URL.path])];
			if (request.HTTPBody.length && request.HTTPBody.length < 10240)
			{
				NSString *str2 = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
				if (str2)
				{
					[[str stringByAppendingString:str2] writeToFile:file atomically:NO encoding:NSUTF8StringEncoding error:nil];
					return;
				}
			}

			[str writeToFile:file atomically:NO encoding:NSUTF8StringEncoding error:nil];
			[request.HTTPBody writeToFile:[file stringByAppendingString:@".dat"] atomically:NO];
		}
	}
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
        // SecureTransport hooks
        MSHookFunction((void *) SSLHandshake,(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
        MSHookFunction((void *) SSLSetSessionOption,(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
        MSHookFunction((void *) SSLCreateContext,(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);
        MSHookFunction((void *) SecTrustEvaluate,(void *)  replaced_SecTrustEvaluate, (void **) &original_SecTrustEvaluate);
        MSHookFunction((void *) SSLRead,(void *)  replaced_SSLRead, (void **) &original_SSLRead);
        MSHookFunction((void *) SSLWrite,(void *)  replaced_SSLWrite, (void **) &original_SSLWrite);

        // CocoaSPDY hooks - https://github.com/twitter/CocoaSPDY
        Class spdyProtocolClass = NSClassFromString(@"SPDYProtocol");
        if (spdyProtocolClass)
        {
            // Disable trust evaluation
            MSHookMessageEx(object_getClass(spdyProtocolClass), NSSelectorFromString(@"setTLSTrustEvaluator:"), (IMP) &newSetTLSTrustEvaluator, (IMP *)&oldSetTLSTrustEvaluator);
            
            MSHookMessageEx(object_getClass(spdyProtocolClass), NSSelectorFromString(@"SecTrustEvaluate:"), (IMP) &newSecTrustEvaluate, (IMP *)&oldSecTrustEvaluate);
            
            // CocoaSPDY works by getting registered as a NSURLProtocol; block that so the Apps switches back to HTTP as SPDY is tricky to proxy
            Class spdyUrlConnectionProtocolClass = NSClassFromString(@"SPDYURLConnectionProtocol");
            MSHookMessageEx(object_getClass(spdyUrlConnectionProtocolClass), NSSelectorFromString(@"registerOrigin:"), (IMP) &newRegisterOrigin, (IMP *)&oldRegisterOrigin);
            
            MSHookMessageEx(NSClassFromString(@"NSURLSessionConfiguration"), NSSelectorFromString(@"setprotocolClasses:"), (IMP) &newSetprotocolClasses, (IMP *)&oldSetprotocolClasses);
        }
}
