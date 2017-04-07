//
//  SSLKillSwitch.m
//  SSLKillSwitch
//
//  Created by Alban Diquet on 7/10/15.
//  Copyright (c) 2015 Alban Diquet. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/SecureTransport.h>
#import <Security/Security.h>
#import <Security/SecPolicy.h>
#import <UIKit/UIKit.h>
#import "MobileGestalt.h"

#if SUBSTRATE_BUILD
#import "substrate.h"
#else
#import "fishhook.h"
#import <dlfcn.h>
#endif

#import "HTTPParser.h"

#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist"
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

CFStringRef oBuildVersion = nil;
CFStringRef oHardwareModel = nil;
CFStringRef oProductType = nil;
CFStringRef oProductVersion = nil;
CFStringRef oSerialNumber = nil;
CFStringRef oUniqueDeviceID = nil;

NSString *nBuildVersion = nil;
NSString *nHardwareModel = nil;
NSString *nProductType = nil;
NSString *nProductVersion = nil;

#pragma mark Utility Functions

static void SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== SSL Kill Switch 2: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}


#if SUBSTRATE_BUILD
// Utility function to read the Tweak's preferences
static BOOL shouldHookFromPreference(NSString *preferenceSetting)
{
    BOOL shouldHook = NO;
    NSMutableDictionary* plist = [[NSMutableDictionary alloc] initWithContentsOfFile:PREFERENCE_FILE];
    //NSString *albumName; 
    if (!plist)
    {
        SSKLog(@"Preference file not found.");
    }
    else
    {

        shouldHook = [[plist objectForKey:preferenceSetting] boolValue];
        if ([plist objectForKey:@"BuildVersion"] != nil) {
            nBuildVersion = [plist objectForKey:@"BuildVersion"];
            SSKLog(@"Loaded BuildVersion = %@", nBuildVersion);
        }
        if ([plist objectForKey:@"HardwareModel"] != nil) {
            nHardwareModel = [plist objectForKey:@"HardwareModel"];
            SSKLog(@"Loaded HardwareModel = %@", nHardwareModel);
        }
        if ([plist objectForKey:@"ProductType"] != nil) {
            nProductType = [plist objectForKey:@"ProductType"];
            SSKLog(@"Loaded ProductType = %@", nProductType);
	}
        if ([plist objectForKey:@"ProductVersion"] != nil) {
            nProductVersion = [plist objectForKey:@"ProductVersion"];
            SSKLog(@"Loaded ProductVersion = %@", nProductVersion);
        }

    }
    return shouldHook;
}
#endif

void writeDataToFile(NSString *appID, void *data, size_t len)
{
    NSString *filename = [NSString stringWithFormat:@"/var/tmp/%@.log", appID];
    NSData *myData = [[NSData alloc] initWithBytes:data length:len];
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filename];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:myData];
        [fileHandle closeFile];
    } else {
        NSError *error = nil;
        [myData writeToFile:filename options:NSDataWritingAtomic error:&error];
    }
}

#pragma mark SSLRead Hook

static OSStatus (*original_SSLRead)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaced_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{
    OSStatus ret = original_SSLRead(context, data, dataLength, processed);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    
    if (appID && [appID isEqualToString:@"com.apple.apsd"]) SSKLog(@"%@ SSLRead() processed=%d", appID, *processed);
    //else SSKLog(@"SSLRead() processed=%d", *processed);

    if (*processed > 0 && [appID isEqualToString:@"com.apple.apsd"]) writeDataToFile(appID, data, *processed);
    
    return ret;
}

/*
static inline void replace_string(void *data, size_t dataLength, char *s1, char *s2)
{
    size_t slen=strlen(s1);
    for (size_t i=0; i< dataLength; i++) {
        if ( ((char*)data)[i] == s1[0]) {
            size_t j;
            for(j=1; j<slen; j++) {
                if (((char*)data)[i+j] != s1[j]) break;
            }
            if (j == slen) {
                memcpy(&(((char*)data)[i]), s2, slen);
            }
        }
    }
}
*/

#pragma mark SSLWrite Hook

static OSStatus (*original_SSLWrite)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaced_SSLWrite(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{

	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	
	if (dataLength > 0 && appID && [appID isEqualToString:@"com.apple.apsd"]) {

        //replace_string(data, dataLength, "iPhone5,3", "iPhone8,2");
/*
        for (size_t i=0; i< dataLength; i++) {
			if ( ((char*)data)[i] == 'i' && ((char*)data)[i+1] == 'P' && ((char*)data)[i+2] == 'h' && ((char*)data)[i+3] == 'o' && ((char*)data)[i+4] == 'n' && ((char*)data)[i+5] == 'e')
			{
				((char*)data)[i+6] = '8';
				((char*)data)[i+8] = '2';
			}
        }
*/
	}

    OSStatus ret = original_SSLWrite(context, data, dataLength, processed);
	
    if (*processed > 0 && [appID isEqualToString:@"com.apple.apsd"]) {
		if (appID) SSKLog(@"%@ SSLWrite() processed=%d", appID, *processed);

		writeDataToFile(appID, data, *processed);

        NSData *myData = [[NSData alloc] initWithBytes:data length:*processed];
        NSString *httpString = isHTTPRequest(myData);
    
        if (httpString != NULL)
        {
			NSString *cmdstr = getHttpRequestCommand(httpString);
			//int headercnt = getHttpRequestHeaders(httpString).count;
			//int bodylen = getHttpRequestBody(httpString).length;
            if (appID) SSKLog(@"%@ SSLWrite() cmd %@, req len=%d", appID, cmdstr, *processed);
        }
    }
    
    return ret;
}


#pragma mark CFReadStreamCreateForHTTPRequest Hook

static CFReadStreamRef (*original_CFReadStreamCreateForHTTPRequest)(CFAllocatorRef alloc, CFHTTPMessageRef request);
static CFReadStreamRef replaced_CFReadStreamCreateForHTTPRequest(CFAllocatorRef alloc, CFHTTPMessageRef request)
{
	if (request != NULL) SSKLog(@"%s: %p", __FUNCTION__, request);
	return original_CFReadStreamCreateForHTTPRequest(alloc, request);
}


#pragma mark CFHTTPMessageCreateRequest Hook

static CFHTTPMessageRef (*original_CFHTTPMessageCreateRequest)(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion);
static CFHTTPMessageRef replaced_CFHTTPMessageCreateRequest(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef url, CFStringRef httpVersion)
{
	CFStringRef hostname = CFURLCopyHostName(url);
	if (hostname != NULL) SSKLog(@"%s: %@", __FUNCTION__, hostname);
	return original_CFHTTPMessageCreateRequest(alloc, requestMethod, url, httpVersion);
}

static void (*original_CFHTTPMessageSetBody)(CFHTTPMessageRef message, CFDataRef bodyData);
static void replaced_CFHTTPMessageSetBody(CFHTTPMessageRef message, CFDataRef bodyData)
{
	SSKLog(@"%s: len=%d", __FUNCTION__, CFDataGetLength(bodyData));
	return original_CFHTTPMessageSetBody(message, bodyData);
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

/*
#pragma mark SSLSetSessionOption Hook

static OSStatus (*original_SSLGetSessionOption)	(SSLContextRef		context,
                                                 SSLSessionOption	option,
                                                 Boolean			*value);

static OSStatus replaced_SSLGetSessionOption	(SSLContextRef		context,
                                                 SSLSessionOption	option,
                                                 Boolean			*value)
{
    OSStatus retval = original_SSLGetSessionOption(context, option, value);
    return retval;
}
*/

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
    } else if (result == errSSLClosedAbort) {
		SSKLog(@"SSLHandshake error errSSLClosedAbort");
    } else if (result != 0 && result != errSSLWouldBlock)
    {
        SSKLog(@"SSLHandshake error %d", result);
    }

    return result;
}


#pragma mark MGCopyAnswer Hook

static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef prop);
static CFPropertyListRef new_MGCopyAnswer(CFStringRef prop) {
    
    CFPropertyListRef retval = nil;
    
    //if (prop == CFSTR("ProductType")) {
    //            SSKLog(@"MGCopyAnswer(%@)\n", prop);
    //            retval = orig_MGCopyAnswer(prop);
    //            CFRelease(retval);
    //            return CFSTR("iPhone8,2");
    //} else {
    SSKLog(@"MGCopyAnswer(%@)\n", prop);
    retval = orig_MGCopyAnswer(prop);
    //}
    return retval;
}

static CFPropertyListRef (*orig_MGCopyMultipleAnswers)(CFArrayRef questions, int __unknown0);
static CFPropertyListRef new_MGCopyMultipleAnswers(CFArrayRef questions, int __unknown0)
{
	SSKLog(@"MGCopyMultipleAnswers()");
	return orig_MGCopyMultipleAnswers(questions, __unknown0);
}

static int (*orig_MGSetAnswer)(CFStringRef question, CFTypeRef answer);
static int new_MGSetAnswer(CFStringRef question, CFTypeRef answer)
{
	SSKLog(@"MGSetAnswer()");
	return orig_MGSetAnswer(question, answer);
}

SecTrustRef addAnchorToTrust(SecTrustRef trust, SecCertificateRef trustedCert);
//SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data); // set allocator to NULL for default


// SecPolicyRef SecPolicyCreateSSL(Boolean server, CFStringRef __nullable hostname)
// SecPolicyRef SecPolicyCreateWithProperties(CFTypeRef policyIdentifier, CFDictionaryRef __nullable properties)
 
 #pragma mark SecPolicyCreateWithProperties Hook
static SecPolicyRef (*original_SecPolicyCreateSSL)(Boolean server, CFStringRef hostname);
static SecPolicyRef replaced_SecPolicyCreateSSL(Boolean server, CFStringRef hostname)
{
    SSKLog(@"%s %@", __FUNCTION__, hostname);
    SecPolicyRef policy = original_SecPolicyCreateSSL(server, NULL);
    return policy;
}
 /*
#pragma mark SSLCopyDistinguishedNames Hook
static OSStatus (*original_SSLCopyDistinguishedNames)(SSLContextRef context, CFArrayRef  *names);
static OSStatus replaced_SSLCopyDistinguishedNames(SSLContextRef context, CFArrayRef  *names)
{
    OSStatus status = original_SSLCopyDistinguishedNames(context, names);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}
*/

#pragma mark SSLCopyPeerTrust hook
static OSStatus (*original_SSLCopyPeerTrust)(SSLContextRef context, SecTrustRef *trust);
static OSStatus replaced_SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust)
{
    OSStatus status = original_SSLCopyPeerTrust(context, trust);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}


#pragma mark SecTrustEvaluate Hook
static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus replaced_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result)
{
    OSStatus status = original_SecTrustEvaluate(trust, result);
    
    //if (*result == kSecTrustResultOtherError) return status;
    //*result = kSecTrustResultProceed;
    SSKLog(@"%s(%d)=%d", __FUNCTION__, *result, status);
    if (*result == kSecTrustResultRecoverableTrustFailure) {
		// add my proxy's der format cert to the anchor cert store
		//NSError *error = nil;
		//NSData *derdata = [[NSData alloc] initWithContentsOfFile:@"/tmp/proxy2_ca.der"];
		//SecCertificateRef certref = SecCertificateCreateWithData(NULL, (CFDataRef)derdata);
		//trust = addAnchorToTrust(trust, certref);
		*result = kSecTrustResultProceed;
	}
    else if (*result == kSecTrustResultUnspecified) *result = kSecTrustResultProceed;
    return status;
}

#pragma mark CocoaSPDY hook

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


#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    // Should we enable the hook ?
    if (shouldHookFromPreference(PREFERENCE_KEY))
    {
        // Substrate-based hooking; only hook if the preference file says so
        //SSKLog(@"Subtrate hook enabled.");

        // SecureTransport hooks
        MSHookFunction((void *) SSLHandshake,(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
        MSHookFunction((void *) SSLSetSessionOption,(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
        MSHookFunction((void *) SSLCreateContext,(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);
        MSHookFunction((void *) SSLRead,(void *)  replaced_SSLRead, (void **) &original_SSLRead);
        MSHookFunction((void *) SSLWrite,(void *)  replaced_SSLWrite, (void **) &original_SSLWrite);
        MSHookFunction((void *) CFReadStreamCreateForHTTPRequest,(void *)  replaced_CFReadStreamCreateForHTTPRequest, (void **) &original_CFReadStreamCreateForHTTPRequest);
        MSHookFunction((void *) CFHTTPMessageCreateRequest,(void *)  replaced_CFHTTPMessageCreateRequest, (void **) &original_CFHTTPMessageCreateRequest);
        MSHookFunction((void *) CFHTTPMessageSetBody,(void *)  replaced_CFHTTPMessageSetBody, (void **) &original_CFHTTPMessageSetBody);
        MSHookFunction((void *) SecTrustEvaluate,(void *)  replaced_SecTrustEvaluate, (void **) &original_SecTrustEvaluate);
        MSHookFunction((void *) SSLCopyPeerTrust,(void *)  replaced_SSLCopyPeerTrust, (void **) &original_SSLCopyPeerTrust);
        MSHookFunction((void *) SecPolicyCreateSSL,(void *)  replaced_SecPolicyCreateSSL, (void **) &original_SecPolicyCreateSSL);

        NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
        // Substrate-based hooking; only hook if the preference file says so
        if (appID && [appID isEqualToString:@"com.apple.apsd"]) {
            MSHookFunction((void*)MGCopyAnswer, (void*)new_MGCopyAnswer, (void**)&orig_MGCopyAnswer);
            MSHookFunction((void*)MGSetAnswer, (void*)new_MGSetAnswer, (void**)&orig_MGSetAnswer);
            MSHookFunction((void*)MGCopyMultipleAnswers, (void*)new_MGCopyMultipleAnswers, (void**)&orig_MGCopyMultipleAnswers);				
            oBuildVersion = orig_MGCopyAnswer(kMGBuildVersion);
            SSKLog(@"oBuildVersion=%@", oBuildVersion);
            oHardwareModel = orig_MGCopyAnswer(kMGHWModel);
            SSKLog(@"oHardwareModel=%@", oHardwareModel);
            oProductType = orig_MGCopyAnswer(kMGProductType);
            SSKLog(@"oProductType=%@", oProductType);
            oProductVersion = orig_MGCopyAnswer(kMGProductVersion);
            SSKLog(@"oProductVersion=%@", oProductVersion);
            oSerialNumber = orig_MGCopyAnswer(kMGSerialNumber);
            SSKLog(@"oSerialNumber=%@", oSerialNumber);
            oUniqueDeviceID = orig_MGCopyAnswer(kMGUniqueDeviceID);
            SSKLog(@"oUniqueDeviceID=%@", oUniqueDeviceID);
            
        }
        // CocoaSPDY hooks - https://github.com/twitter/CocoaSPDY
        // TODO: Enable these hooks for the fishhook-based hooking so it works on OS X too
        Class spdyProtocolClass = NSClassFromString(@"SPDYProtocol");
        if (spdyProtocolClass)
        {
            // Disable trust evaluation
            MSHookMessageEx(object_getClass(spdyProtocolClass), NSSelectorFromString(@"setTLSTrustEvaluator:"), (IMP) &newSetTLSTrustEvaluator, (IMP *)&oldSetTLSTrustEvaluator);
            
            //MSHookMessageEx(object_getClass(spdyProtocolClass), NSSelectorFromString(@"SecTrustEvaluate:"), (IMP) &newSecTrustEvaluate, (IMP *)&oldSecTrustEvaluate);
            
            // CocoaSPDY works by getting registered as a NSURLProtocol; block that so the Apps switches back to HTTP as SPDY is tricky to proxy
            Class spdyUrlConnectionProtocolClass = NSClassFromString(@"SPDYURLConnectionProtocol");
            MSHookMessageEx(object_getClass(spdyUrlConnectionProtocolClass), NSSelectorFromString(@"registerOrigin:"), (IMP) &newRegisterOrigin, (IMP *)&oldRegisterOrigin);
            
            MSHookMessageEx(NSClassFromString(@"NSURLSessionConfiguration"), NSSelectorFromString(@"setprotocolClasses:"), (IMP) &newSetprotocolClasses, (IMP *)&oldSetprotocolClasses);
        }
    }
    else
    {
        SSKLog(@"Subtrate hook disabled.");
    }

}

