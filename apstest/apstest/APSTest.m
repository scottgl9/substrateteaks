//
//  APSTest.m
#import <Foundation/Foundation.h>
#import <Security/SecureTransport.h>
#import <UIKit/UIKit.h>

#import <substrate.h>
#import <Security/SecureTransport.h>

//#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.scottgl.mgtest.plist"

#pragma mark Utility Functions

static void SSKLog(NSString *format, ...)
{
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== com.scottgl.apstest: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
}


#pragma mark SSLWrite Hook

//Hook the SSLWrite()
static OSStatus (*original_SSLWrite)(
                         SSLContextRef context, 
                         const void *data, 
                         size_t dataLength, 
                         size_t *processed);

static OSStatus replaced_SSLWrite(SSLContextRef context, 
                                  const void *data, 
                                  size_t dataLength, 
                                  size_t *processed){
    
    NSString *bundleID = [[NSBundle mainBundle]bundleIdentifier];
//    NSString *appName = [[[NSBundle mainBundle]infoDictionary] objectForKey:@"CFBundleDisplayName"];
    SSKLog(@"%@ SSLWrite len :%zu",bundleID,dataLength);
    //NSData *ocData = [NSData dataWithBytes:data length:dataLength];
    //NSString *ocStr = [[NSString alloc] initWithData:ocData encoding:NSUTF8StringEncoding];
//    NSLog(@"SSLWrite data:%@",ocStr);
//    NSArray *infoArray = [ocStr componentsSeparatedByString:@"\r\n"];
//    NSMutableDictionary *infoDict = [[NSMutableDictionary alloc] init];
/*
    int count = infoArray.count;
    for(int i=0;i<count;i++){
        NSString *info = [infoArray objectAtIndex:i];
        NSLog(@"%@ SSLWrite data:%@",bundleID,info);
        
    }        
*/
//    NSLog(@"SSLWrite data:%s",(char *)data);
    return original_SSLWrite(context,data,dataLength,processed);
}

#pragma mark Dylib Constructor

__attribute__((constructor)) static void init(int argc, const char **argv)
{
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    NSLog(@"SSL Kill Switch - Hook Enabled.");
    MSHookFunction((void *) SSLWrite,(void *)  replaced_SSLWrite, (void **) &original_SSLWrite);
    [pool drain];
}
