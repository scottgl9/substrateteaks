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

#if SUBSTRATE_BUILD
#import "substrate.h"
#else
#import "fishhook.h"
#import <dlfcn.h>
#endif

#import "HTTPParser.h"

#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist"
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

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
    
    if (!plist)
    {
        SSKLog(@"Preference file not found.");
    }
    else
    {
        shouldHook = [[plist objectForKey:preferenceSetting] boolValue];
        //SSKLog(@"Preference set to %d.", shouldHook);
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
    
    //if (appID) SSKLog(@"%@ SSLRead() processed=%d", appID, *processed);
    //else SSKLog(@"SSLRead() processed=%d", *processed);

    if (*processed > 0) writeDataToFile(appID, data, *processed);
    
    return ret;
}



#pragma mark SSLWrite Hook

static OSStatus (*original_SSLWrite)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaced_SSLWrite(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
/*
	if (HttpRequestReplaceString(data, dataLength, "iPhone5,3", "iPhone7,1")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced %s -> %s", appID, "iPhone5,3", "iPhone7,1"); }
    } 
    if (HttpRequestReplaceString(data, dataLength, "18:af:61:ed:30:b1", "50:7a:55:be:1e:6a")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 18:af:61:ed:30:b1 -> 50:7a:55:be:1e:6a", appID); }
    //} else if (HttpRequestReplaceString(data, dataLength, "AEA5CCE143668D0EFB4CE1F2C94C966A6496C6AA", "8CB15EE4C8002199070D9500BB8FB183B02713A5CA2A6B92DB5E75CE15536182")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced AEA5CCE143668D0EFB4CE1F2C94C966A6496C6AA -> 8CB15EE4C8002199070D9500BB8FB183B02713A5CA2A6B92DB5E75CE15536182", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "ME553", "MGC02")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced ME553 -> MGC02", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "c1ffc3c03997b19d9dcf68fb81f117226539ef6b", "a9a08959739fda70188f69dd5691e59e905270ca")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced c1ffc3c03997b19d9dcf68fb81f117226539ef6b -> a9a08959739fda70188f69dd5691e59e905270ca", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "18:af:61:ed:30:af", "50:7a:55:be:1e:68")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 18:af:61:ed:30:af -> 50:7a:55:be:1e:68", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "89014103277446203312", "89014104277367212663")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 89014103277446203312 -> 89014104277367212663", appID); }
    //} else if (HttpRequestReplaceString(data, dataLength, "armv7s", "arm64")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced armv7s -> arm64", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "#3b3b3c", "#e1e4e3")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced #3b3b3c -> #e1e4e3", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "310410744620331", "310410736721266")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 310410744620331 -> 310410736721266", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "357991051309069", "354451066373298")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 357991051309069 -> 354451066373298", appID); }
    //} else if (HttpRequestReplaceString(data, dataLength, "s5l8950x", "t7000")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced s5l8950x -> t7000", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "35799105130906", "35445106637329")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 35799105130906 -> 35445106637329", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "F78L5D2UFNDD", "C39Q55U0G5QG")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced F78L5D2UFNDD -> C39Q55U0G5QG", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "18:af:61:ed:30:b0", "50:7a:55:be:1e:69")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced 18:af:61:ed:30:b0 -> 50:7a:55:be:1e:69", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "C7H329505LVF284ZD", "C07530506N7G166J")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced C7H329505LVF284ZD -> C07530506N7G166J", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "N48AP", "N56AP")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced N48AP -> N56AP", appID); }
    }
    if (HttpRequestReplaceString(data, dataLength, "#f5f4f7", "#d7d9d8")){ if (appID) { SSKLog(@"%@ SSLWrite() Replaced #f5f4f7 -> #d7d9d8", appID); } }
*/
    OSStatus ret = original_SSLWrite(context, data, dataLength, processed);
    
    if (*processed > 0) {
		//if (appID) SSKLog(@"%@ SSLWrite() processed=%d", appID, *processed);

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


SecTrustRef addAnchorToTrust(SecTrustRef trust, SecCertificateRef trustedCert);
//SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data); // set allocator to NULL for default

// Apr  2 07:14:08 Scott-Glovers-iPhone apsd[3051] <Warning>: === SSL Kill Switch 2: replaced_SecTrustEvaluate(4)=0 
// Apr  2 07:14:08 Scott-Glovers-iPhone syncdefaultsd[3066] <Warning>: === SSL Kill Switch 2: com.apple.syncdefaultsd SSLWrite() cmd POST /setAPNSToken HTTP/1.1, req len=867 
// Apr  2 07:14:09 Scott-Glovers-iPhone apsd[3051] <Error>:  SecTrustEvaluate  [leaf AnchorApple CheckIntermediateMarkerOid CheckLeafMarkerOid SSLHostname] 
// Apr  2 07:14:09 Scott-Glovers-iPhone apsd[3051] <Warning>: === SSL Kill Switch 2: replaced_SecTrustEvaluate(5)=0 

// SecPolicyRef SecPolicyCreateSSL(Boolean server, CFStringRef __nullable hostname)
// SecPolicyRef SecPolicyCreateWithProperties(CFTypeRef policyIdentifier, CFDictionaryRef __nullable properties)
 
 #pragma mark SecPolicyCreateWithProperties Hook
static SecPolicyRef (*original_SecPolicyCreateSSL)(Boolean server, CFStringRef hostname);
static SecPolicyRef replaced_SecPolicyCreateSSL(Boolean server, CFStringRef hostname)
{
    SecPolicyRef policy = original_SecPolicyCreateSSL(server, hostname);
    SSKLog(@"%s %@", __FUNCTION__, hostname);
    return policy;
}
 
#pragma mark SecPolicyCreateWithProperties Hook
static SecPolicyRef (*original_SecPolicyCreateWithProperties)(CFTypeRef policyIdentifier, CFDictionaryRef properties);
static SecPolicyRef replaced_SecPolicyCreateWithProperties(CFTypeRef policyIdentifier, CFDictionaryRef properties)
{
    SecPolicyRef policy = original_SecPolicyCreateWithProperties(policyIdentifier, properties);
    SSKLog(@"%s", __FUNCTION__);
    return policy;
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
        MSHookFunction((void *) SecPolicyCreateWithProperties,(void *)  replaced_SecPolicyCreateWithProperties, (void **) &original_SecPolicyCreateWithProperties);
        MSHookFunction((void *) SecPolicyCreateSSL,(void *)  replaced_SecPolicyCreateSSL, (void **) &original_SecPolicyCreateSSL);

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

