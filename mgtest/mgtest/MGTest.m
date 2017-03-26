//
//  MGTest.m
#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <UIKit/UIKit.h>

#import <substrate.h>
#import "MobileGestalt.h"

//#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.scottgl.mgtest.plist"

//const char *propstr = CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman);
// MGCopyAnswer_internal(eZS2J+wspyGxqNYZeZ/sbA) = <90b0ed7a 0e03>
// MGCopyAnswer_internal(gI6iODv8MZuiP0IA+efJCw) = 90:b0:ed:7a:0e:03
// MGCopyAnswer_internal(jSDzacs4RYWnWxn142UBLQ) = <90b0ed7a 0e04>
// MGCopyAnswer_internal(k5lVWbXuiZHLA17KGiVUAA) = 90:b0:ed:7a:0e:04
// MGCopyAnswer_internal(TF31PAB6aO8KAbPyNKSxKA) = 3404706751931322
// MGCopyAnswer_internal(nFRqKto/RuQAV1P+0/qkBA) = <87cda23a 7230769e f6aa1ded 8a99a5d3 e65b9d42>
// MGCopyAnswer_internal(oBbtJ8x+s1q0OkaiocPuog) = <38040000 80070000 46010000 00004040 00000000 09000000>
// MGCopyAnswer_internal(main-screen-width) = 1080
// MGCopyAnswer_internal(DeviceColor) = #272728
// MGCopyAnswer_internal(DeviceEnclosureColor) = #b9b7ba
// MGCopyAnswer_internal(marketing-name) = iPhone 6s Plus


#pragma mark Utility Functions

static void SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== com.scottgl.mgtest: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}


static CFPropertyListRef (*orig_MGCopyAnswer_internal)(CFStringRef prop, uint32_t* outTypeCode);
CFPropertyListRef new_MGCopyAnswer_internal(CFStringRef prop, uint32_t* outTypeCode) {
    CFPropertyListRef retval = orig_MGCopyAnswer_internal(prop, outTypeCode);
	SSKLog(@"MGCopyAnswer_internal(%s)\n", CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman));
    return retval;
}


//extern "C" MGCopyAnswer(CFStringRef prop);
#pragma mark MGCopyAnswer Hook

static CFPropertyListRef (*orig_MGCopyAnswer)(CFStringRef prop);
CFPropertyListRef new_MGCopyAnswer(CFStringRef prop) {
    //SSKLog(@"MGCopyAnswer(%@)\n", prop);
    CFPropertyListRef retval = orig_MGCopyAnswer(prop);

    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];

    // Substrate-based hooking; only hook if the preference file says so
    //if (appID && [appID isEqualToString:@"com.apple.CrashReporter"]) return retval;
    //if (appID && [appID isEqualToString:@"com.apple.icloud.fmfd"]) return retval;
    //if (appID && [appID isEqualToString:@"com.apple.springboard"]) return retval;
    //if (appID && [appID isEqualToString:@"com.apple.accessibility.AccessibilityUIServer"]) return retval;  
    // Substrate-based hooking; only hook if the preference file says so
    if (appID && ([appID isEqualToString:@"com.apple.akd"] ||
                  [appID isEqualToString:@"com.apple.apsd"] ||
                  [appID isEqualToString:@"com.apple.AOSNotification"]// ||
                  //[appID isEqualToString:@"com.apple.accountsd"] ||
                  //[appID isEqualToString:@"com.apple.securityd"] ||
                  //[appID isEqualToString:@"com.apple.security.cloudkeychainproxy3"] ||
                  //[appID isEqualToString:@"com.apple.locationd"] ||
                  //[appID isEqualToString:@"com.apple.cloudd"] ||
                  //[appID isEqualToString:@"com.apple.identityservicesd"]// ||
                  //[appID isEqualToString:@"com.apple.syncdefaultsd"] ||
                  //[appID isEqualToString:@"com.apple.dataaccess.dataaccessd"] ||
                  //[appID isEqualToString:@"com.apple.icloud.findmydeviced"] ||
                  /*[appID isEqualToString:@"com.apple.icloud.fmfd"]*/)) {

    if (CFGetTypeID(retval) == CFStringGetTypeID()) {
        SSKLog(@"MGCopyAnswer(%@) (CFString)\n", prop);
/*
        const char *propstr = CFStringGetCStringPtr(prop, kCFStringEncodingMacRoman);
        if (strcmp(propstr, "ProductType") == 0) {
            CFRelease(retval);
            retval = CFSTR("iPhone8,2");
        }
        else if (strcmp(propstr, "ProductVersion") == 0) {
            //CFRelease(retval);
            //retval = CFSTR("9.3.3");
        }
        else if (strcmp(propstr, "BuildVersion") == 0) {
            //CFRelease(retval);
            //retval = CFSTR("13G34");
        }
        else if (strcmp(propstr, "UniqueDeviceID") == 0) {
            CFRelease(retval);
            retval = CFSTR("61dd7b522bb9d7cf78008dd4ae502b634b93e970");
        }
        else if (strcmp(propstr, "DeviceColor") == 0) {
            CFRelease(retval);
            retval = CFSTR("#e4e7e8");
        }
        else if (strcmp(propstr, "DeviceEnclosureColor") == 0) {
            CFRelease(retval);
            retval = CFSTR("#e4c1b9");
        }
        else if (strcmp(propstr, "SerialNumber") == 0 || strcmp(propstr, "VasUgeSzVyHdB27g2XpN0g") == 0) {
            CFRelease(retval);
            retval = CFSTR("F2PQLYPWGRX5");
        }
*/
    } else if (CFGetTypeID(retval) == CFArrayGetTypeID())
    {
        SSKLog(@"MGCopyAnswer(%@) (CFArray)\n", prop);
/*
        CFIndex count = CFArrayGetCount(retval);
        for (int i=0;i<count;i++) {
            CFStringRef string = CFArrayGetValueAtIndex(retval, i);
            SSKLog(@"MGCopyAnswer(%@) (CFArray) = %@\n", prop, string);
        }
*/
    } else if (CFGetTypeID(retval) == CFDictionaryGetTypeID())
    {
        SSKLog(@"MGCopyAnswer(%@) (CFDictionary)\n", prop);
/*
        const void * keys;
        const void * values;
        CFDictionaryGetKeysAndValues(retval, &keys, &values);
        for (int i = 0; i < CFDictionaryGetCount(retval); i++) {
            const char * keyStr = CFStringGetCStringPtr((CFStringRef)&keys[i], CFStringGetSystemEncoding());
            const char * valStr = CFStringGetCStringPtr((CFStringRef)&values[i], CFStringGetSystemEncoding());
            SSKLog(@"MGCopyAnswer(%@) (CFDictionary): key=%s value=%s\n", prop, keyStr, valStr);
        }
*/
    }
    else if (CFGetTypeID(retval) == CFNumberGetTypeID())
    {
        SSKLog(@"MGCopyAnswer(%@) (CFNumber) = %@\n", prop, retval);
    } else if (CFGetTypeID(retval) == CFBooleanGetTypeID())
    {
        SSKLog(@"MGCopyAnswer(%@) (CFBoolean) = %@\n", prop, retval);
    } else if (CFGetTypeID(retval) == CFDataGetTypeID())
    {
        SSKLog(@"MGCopyAnswer(%@) (CFData)\n", prop);
    } else
    {
        SSKLog(@"MGCopyAnswer(%@) (CFUnknown) = %@\n", prop, retval);
    }
    }
    return retval;
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    //NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
/*
    // Substrate-based hooking; only hook if the preference file says so
    if (appID && ([appID isEqualToString:@"com.apple.akd"] ||
                  [appID isEqualToString:@"com.apple.apsd"] ||
                  [appID isEqualToString:@"com.apple.AOSNotification"] ||
                  [appID isEqualToString:@"com.apple.accountsd"] ||
                  //[appID isEqualToString:@"com.apple.securityd"] ||
                  //[appID isEqualToString:@"com.apple.security.cloudkeychainproxy3"] ||
                  [appID isEqualToString:@"com.apple.locationd"] ||
                  [appID isEqualToString:@"com.apple.cloudd"] ||
                  [appID isEqualToString:@"com.apple.identityservicesd"]// ||
                  //[appID isEqualToString:@"com.apple.syncdefaultsd"] ||
                  //[appID isEqualToString:@"com.apple.dataaccess.dataaccessd"] ||
                  //[appID isEqualToString:@"com.apple.icloud.findmydeviced"] ||
                  [appID isEqualToString:@"com.apple.icloud.fmfd"])) {
*/
        //SSKLog(@"com.scottgl.mgtest %@.", appID);

        uint8_t MGCopyAnswer_arm64_impl[8] = {0x01, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0x14};
        const uint8_t* MGCopyAnswer_ptr = (const uint8_t*) MGCopyAnswer;
        if (memcmp(MGCopyAnswer_ptr, MGCopyAnswer_arm64_impl, 8) == 0) {
            MSHookFunction((void*)MGCopyAnswer_ptr + 8, (void*)new_MGCopyAnswer_internal, (void**)&orig_MGCopyAnswer_internal);
        } else {
            MSHookFunction((void*)MGCopyAnswer_ptr, (void*)new_MGCopyAnswer, (void**)&orig_MGCopyAnswer);
        }
}

