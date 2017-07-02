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
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
//#import <IOKit/hid/IOHIDBase.h>
typedef struct __IOHIDDevice * IOHIDDeviceRef;

/*! @typedef IOHIDElementRef
 * 	This is the type of a reference to the IOHIDElement.
 * 	*/
typedef struct __IOHIDElement * IOHIDElementRef;

/*! @typedef IOHIDValueRef
 * 	This is the type of a reference to the IOHIDValue.
 * 	*/
typedef struct __IOHIDValue * IOHIDValueRef;

#import "MobileGestalt.h"
#import "liblockdown.h"

#if !defined(CCN_UNIT_SIZE)
#if defined(__x86_64__)
#define CCN_UNIT_SIZE  8
#elif defined(__arm__) || defined(__i386__)
#define CCN_UNIT_SIZE  4
#else
#define CCN_UNIT_SIZE  2
#endif
#endif /* !defined(CCN_UNIT_SIZE) */

#if  CCN_UNIT_SIZE == 8
typedef uint64_t cc_unit;          // 64 bit unit
//typedef uint128_t cc_dunit;         // 128 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  6  // 2^6 = 64 bits
#define CC_UNIT_C(x) UINT64_C(x)
#elif  CCN_UNIT_SIZE == 4
typedef uint32_t cc_unit;          // 32 bit unit
typedef uint64_t cc_dunit;         // 64 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  5  // 2^5 = 32 bits
#define CC_UNIT_C(x) UINT32_C(x)
#elif CCN_UNIT_SIZE == 2
typedef uint16_t cc_unit;          // 16 bit unit
typedef uint32_t cc_dunit;         // 32 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  4  // 2^4 = 16 bits
#define CC_UNIT_C(x) UINT16_C(x)
#elif CCN_UNIT_SIZE == 1
typedef uint8_t cc_unit;           // 8 bit unit
typedef uint16_t cc_dunit;         // 16 bit double width unit
#define CCN_LOG2_BITS_PER_UNIT  3  // 2^3 = 8 bits
#define CC_UNIT_C(x) UINT8_C(x)
#else
#error invalid CCN_UNIT_SIZE
#endif

struct ccdigest_ctx {
    union {
        uint8_t u8;
        uint32_t u32;
        uint64_t u64;
        cc_unit ccn;
    } state;
} __attribute((aligned(8)));

typedef union {
    struct ccdigest_ctx *hdr;
} ccdigest_ctx_t __attribute__((transparent_union));

struct ccdigest_state {
    union {
        uint8_t u8;
        uint32_t u32;
        uint64_t u64;
        cc_unit ccn;
    } state;
} __attribute((aligned(8)));

typedef union {
    struct ccdigest_state *hdr;
    struct ccdigest_ctx *_ctx;
    ccdigest_ctx_t _ctxt;
} ccdigest_state_t __attribute__((transparent_union));

struct ccdigest_info {
    unsigned long output_size;
    unsigned long state_size;
    unsigned long block_size;
    unsigned long oid_size;
    unsigned char *oid;
    const void *initial_state;
    void(*compress)(ccdigest_state_t state, unsigned long nblocks,
                    const void *data);
    void(*final)(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                 unsigned char *digest);
};

struct cchmac_ctx {
    uint8_t b[8];
} __attribute__((aligned(8)));

typedef union {
    struct cchmac_ctx *hdr;
    ccdigest_ctx_t digest;
} cchmac_ctx_t __attribute__((transparent_union));

#if SUBSTRATE_BUILD
#import "substrate.h"
#else
#import "fishhook.h"
#import <dlfcn.h>
#endif

#import "HTTPParser.h"

#define PREFERENCE_FILE @"/private/var/mobile/Library/Preferences/com.nablac0d3.SSLKillSwitchSettings.plist"
#define PREFERENCE_KEY @"shouldDisableCertificateValidation"

// Jun 18 05:19:38 iPhone lockdownd[6712] <Warning>: === SSL Kill Switch 2: MGCopyAnswer(UniqueDeviceIDData)=<3fbace30 9f3896cb 8607d7e1 e31d6d99 45536b61> 

NSString *oBuildVersion = nil;
NSString *oDeviceColor = nil;
NSString *oDeviceEnclosureColor = nil;
NSString *oHardwareModel = nil;
NSString *oModelNumber = nil;
NSString *oProductType = nil;
NSString *oProductVersion = nil;
NSString *oSerialNumber = nil;
NSString *oUniqueDeviceID = nil;
NSString *oWifiAddress = nil;
NSString *oHWModelStr = nil;
NSString *oHardwarePlatform = nil;
NSString *oBluetoothAddress = nil;
NSString *oEthernetMacAddress = nil;
NSNumber *oUniqueChipID = nil;
NSNumber *oDieId = nil;
NSString *oMLBSerialNumber = nil;
NSString *oFirmwareVersion = nil;
NSString *oCPUArchitecture = nil;
NSString *oWirelessBoardSnum = nil;
NSNumber *oBasebandCertId = nil;
NSString *oBasebandFirmwareVersion = nil;
NSString *oInternationalMobileEquipmentIdentity = nil;
NSString *oMobileEquipmentIdentifier = nil;

NSString *nBuildVersion = nil;
NSString *nDeviceColor = nil;
NSString *nDeviceEnclosureColor = nil;
NSString *nHardwareModel = nil;
NSString *nModelNumber = nil;
NSString *nProductType = nil;
NSString *nProductVersion = nil;
NSString *nSerialNumber = nil;
NSString *nUniqueDeviceID = nil;
NSString *nWifiAddress = nil;
NSString *nHWModelStr = nil;
NSString *nHardwarePlatform = nil;
NSString *nBluetoothAddress = nil;
NSString *nEthernetMacAddress = nil;
NSString *nUniqueChipID = nil;
NSNumber *nDieId = nil;
NSString *nMLBSerialNumber = nil;
NSString *nFirmwareVersion = nil;
NSString *nCPUArchitecture = nil;
NSString *nWirelessBoardSnum = nil;
NSNumber *nBasebandCertId = nil;
NSNumber *nBasebandChipId = nil;
NSString *nBasebandFirmwareVersion = nil;
NSString *nInternationalMobileEquipmentIdentity = nil;
NSString *nMobileEquipmentIdentifier = nil;
NSData *nUniqueDeviceIDData = nil;
NSString *nBasebandMasterKeyHash = nil;
NSNumber *nBoardId= nil;
NSString *nBasebandVersion = nil;
NSString *nIntegratedCircuitCardIdentity = nil;
NSArray *nCarrierBundleInfoArray = nil;


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
        if ([plist objectForKey:@"BuildVersion"] != nil) {
            nBuildVersion = [plist objectForKey:@"BuildVersion"];
            //SSKLog(@"Loaded BuildVersion = %@", nBuildVersion);
        }
        if ([plist objectForKey:@"DeviceColor"] != nil) {
			nDeviceColor = [plist objectForKey:@"DeviceColor"];
			//SSKLog(@"Loaded nDeviceColor = %@", nDeviceColor);
        }
        if ([plist objectForKey:@"DeviceEnclosureColor"] != nil) {
			nDeviceEnclosureColor = [plist objectForKey:@"DeviceEnclosureColor"];
			//SSKLog(@"Loaded nDeviceEnclosureColor = %@", nDeviceEnclosureColor);
        }
		if ([plist objectForKey:@"HardwareModel"] != nil) {
            nHardwareModel = [plist objectForKey:@"HardwareModel"];
            //SSKLog(@"Loaded HardwareModel = %@", nHardwareModel);
        }
        if ([plist objectForKey:@"ModelNumber"] != nil) {
            nModelNumber = [plist objectForKey:@"ModelNumber"];
            //SSKLog(@"Loaded ModelNumber = %@", nModelNumber);
        }
        if ([plist objectForKey:@"ProductType"] != nil) {
            nProductType = [plist objectForKey:@"ProductType"];
            //SSKLog(@"Loaded ProductType = %@", nProductType);
        }
        if ([plist objectForKey:@"ProductVersion"] != nil) {
            nProductVersion = [plist objectForKey:@"ProductVersion"];
            //SSKLog(@"Loaded ProductVersion = %@", nProductVersion);
        }
        if ([plist objectForKey:@"SerialNumber"] != nil) {
            nSerialNumber = [plist objectForKey:@"SerialNumber"];
            //SSKLog(@"Loaded SerialNumber = %@", nSerialNumber);
        }
        if ([plist objectForKey:@"UniqueDeviceID"] != nil) {
            nUniqueDeviceID = [plist objectForKey:@"UniqueDeviceID"];
            //SSKLog(@"Loaded UniqueDeviceID = %@", nUniqueDeviceID);
        }
        if ([plist objectForKey:@"WifiAddress"] != nil) {
            nWifiAddress = [plist objectForKey:@"WifiAddress"];
            //SSKLog(@"Loaded WifiAddress = %@", nWifiAddress);
        }
        if ([plist objectForKey:@"HWModelStr"] != nil) {
            nHWModelStr = [plist objectForKey:@"HWModelStr"];
            //SSKLog(@"Loaded HWModelStr = %@", nHWModelStr);
        }
        if ([plist objectForKey:@"HardwarePlatform"] != nil) {
            nHardwarePlatform = [plist objectForKey:@"HardwarePlatform"];
            //SSKLog(@"Loaded HardwarePlatform = %@", HardwarePlatform);
        }
        
        if ([plist objectForKey:@"BluetoothAddress"] != nil) {
            nBluetoothAddress = [plist objectForKey:@"BluetoothAddress"];
        }
        if ([plist objectForKey:@"EthernetMacAddress"] != nil) {
            nEthernetMacAddress = [plist objectForKey:@"EthernetMacAddress"];
        }
        if ([plist objectForKey:@"UniqueChipID"] != nil) {
            nUniqueChipID = [plist objectForKey:@"UniqueChipID"];
        }
        if ([plist objectForKey:@"DieId"] != nil) {
            nDieId = [plist objectForKey:@"DieId"];
        }
        if ([plist objectForKey:@"MLBSerialNumber"] != nil) {
            nMLBSerialNumber = [plist objectForKey:@"MLBSerialNumber"];
        }
        if ([plist objectForKey:@"FirmwareVersion"] != nil) {
            nFirmwareVersion = [plist objectForKey:@"FirmwareVersion"];
        }
        if ([plist objectForKey:@"CPUArchitecture"] != nil) {
            nCPUArchitecture = [plist objectForKey:@"CPUArchitecture"];
        }
        if ([plist objectForKey:@"WirelessBoardSnum"] != nil) {
            nWirelessBoardSnum = [plist objectForKey:@"WirelessBoardSnum"];
        }
        if ([plist objectForKey:@"BasebandCertId"] != nil) {
            nBasebandCertId = [plist objectForKey:@"BasebandCertId"];
        }
         if ([plist objectForKey:@"BasebandChipId"] != nil) {
            nBasebandChipId = [plist objectForKey:@"BasebandChipId"];
        }
        if ([plist objectForKey:@"InternationalMobileEquipmentIdentity"] != nil) {
            nInternationalMobileEquipmentIdentity = [plist objectForKey:@"InternationalMobileEquipmentIdentity"];
        }
        if ([plist objectForKey:@"MobileEquipmentIdentifier"] != nil) {
            nMobileEquipmentIdentifier = [plist objectForKey:@"MobileEquipmentIdentifier"];
        }
        if ([plist objectForKey:@"UniqueDeviceIDData"] != nil) {
            nUniqueDeviceIDData = [plist objectForKey:@"UniqueDeviceIDData"];
        }
         if ([plist objectForKey:@"BasebandMasterKeyHash"] != nil) {
            nBasebandMasterKeyHash = [plist objectForKey:@"BasebandMasterKeyHash"];
        }
        if ([plist objectForKey:@"BoardId"] != nil) {
            nBoardId = [plist objectForKey:@"BoardId"];
        }
        if ([plist objectForKey:@"BasebandVersion"] != nil) {
            nBasebandVersion = [plist objectForKey:@"BasebandVersion"];
        }
        if ([plist objectForKey:@"CarrierBundleInfoArray"] != nil) {
	    nCarrierBundleInfoArray = [plist objectForKey:@"CarrierBundleInfoArray"];
        }
        if ([plist objectForKey:@"IntegratedCircuitCardIdentity"] != nil) {
		nIntegratedCircuitCardIdentity = [plist objectForKey:@"IntegratedCircuitCardIdentity"];
	}
    }
    return shouldHook;
}

#endif

void writeDataToFile(NSString *appID, NSString *name, const void *data, size_t len, unsigned long output_size)
{
    if (len == 4096) return;
    NSString *filename = [NSString stringWithFormat:@"/var/tmp/%@_%@.bin", appID, name];
    NSData *myData = nil;
    if (data != NULL) myData = [[NSData alloc] initWithBytes:data length:len];
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filename];
    NSString *lenstr = nil;
    if (output_size != 0) lenstr = [[NSString alloc] initWithFormat:@"\nSHA%d_INIT", (int)(output_size * 8)];
    else lenstr = [[NSString alloc] initWithFormat:@"\n%d\n", (int)len];
    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[lenstr dataUsingEncoding:NSUTF8StringEncoding]];
	if (data != NULL) {
		[fileHandle seekToEndOfFile];
        	[fileHandle writeData:myData];
	}
        [fileHandle closeFile];
    } else {
        NSError *error = nil;
        [[NSFileManager defaultManager] createFileAtPath:filename contents:nil attributes:nil];
	NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filename];
	if (fileHandle) {
            [fileHandle seekToEndOfFile];
            [fileHandle writeData:[lenstr dataUsingEncoding:NSUTF8StringEncoding]];
	    if (data != NULL) {
	    	[fileHandle seekToEndOfFile];
            	[fileHandle writeData:myData];
	    }
            [fileHandle closeFile];
	} else {
            [myData writeToFile:filename options:NSDataWritingAtomic error:&error];
	}
    }
}

void writeAsHexToFile(NSString *appID, NSString *name, unsigned char *data, size_t len)
{
    NSString *filename = [NSString stringWithFormat:@"/var/tmp/%@_%@.bin", appID, name];
    NSData *myData = [[NSData alloc] initWithBytes:data length:len];
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForWritingAtPath:filename];

    NSUInteger          dataLength  = (NSUInteger)len;
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];

    for (size_t i = 0; i < len; ++i)
    {
        [hexString appendFormat:@"%02x", (unsigned int)data[i]];
    }

    [hexString appendString:@"\n"];

    NSString *str = [NSString stringWithString:hexString];

    if (fileHandle) {
        [fileHandle seekToEndOfFile];
        [fileHandle writeData:[str dataUsingEncoding:NSUTF8StringEncoding]];
        [fileHandle closeFile];
    } else {
        NSError *error = nil;
        [myData writeToFile:filename options:NSDataWritingAtomic error:&error];
    }
}

/*
#pragma mark SSLRead Hook

static OSStatus (*original_SSLRead)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaced_SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{
    OSStatus ret = original_SSLRead(context, data, dataLength, processed);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    
    //if (appID && [appID isEqualToString:@"com.apple.apsd"]) SSKLog(@"%@ SSLRead() processed=%d", appID, *processed);
    //else SSKLog(@"SSLRead() processed=%d", *processed);

    if (*processed > 0 && [appID isEqualToString:@"com.apple.apsd"]) writeDataToFile(appID, data, *processed);
    
    return ret;
}

static inline int replace_string(void *data, size_t dataLength, const char *s1, const char *s2)
{
    int retval = 0;
    size_t slen=strlen(s1);
    for (size_t i=0; i< dataLength; i++) {
        if ( ((char*)data)[i] == s1[0]) {
            size_t j;
            for(j=1; j<slen; j++) {
                if (((char*)data)[i+j] != s1[j]) break;
            }
            if (j == slen) {
                retval = 1;
                memcpy(&(((char*)data)[i]), s2, slen);
            }
        }
    }
    return retval;
}
*/
#define REPLACE_STRING(A, B, C, D, E) if (replace_string(A, B, C, D)) { SSKLog(@"%@ Replaced %s -> %s", E, C, D); }

#pragma mark SSLWrite Hook

static OSStatus (*original_SSLWrite)(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
static OSStatus replaced_SSLWrite(SSLContextRef context, void *data, size_t dataLength, size_t *processed)
{

    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
/*
    if (dataLength > 0 && appID && [appID isEqualToString:@"com.apple.apsd"]) 
    {
        if (nProductType != nil) REPLACE_STRING(data, dataLength, [oProductType UTF8String], [nProductType UTF8String], appID);     
    }
*/
    OSStatus ret = original_SSLWrite(context, data, dataLength, processed);

    if (*processed > 0 /*&& [appID isEqualToString:@"com.apple.apsd"]*/) {
        if (appID) SSKLog(@"%@ SSLWrite() processed=%d", appID, *processed);

        writeDataToFile(appID, @"ssl", data, *processed, 0);
/*
        NSData *myData = [[NSData alloc] initWithBytes:data length:*processed];
        NSString *httpString = isHTTPRequest(myData);
    
        if (httpString != NULL)
        {
            NSString *cmdstr = getHttpRequestCommand(httpString);
            //int headercnt = getHttpRequestHeaders(httpString).count;
            //int bodylen = getHttpRequestBody(httpString).length;
            if (appID) SSKLog(@"%@ SSLWrite() cmd %@, req len=%d", appID, cmdstr, *processed);
        }
*/
    }

    return ret;
}
/*
#pragma mark lockdown_copy_value

static CFPropertyListRef (*original_lockdown_copy_value)(LockdownConnectionRef connection, CFStringRef domain, CFStringRef key);
static CFPropertyListRef replaced_lockdown_copy_value(LockdownConnectionRef connection, CFStringRef domain, CFStringRef key)
{
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    CFPropertyListRef retval = original_lockdown_copy_value(connection, domain, key);
    if (appID) SSKLog(@"%@ lockdown_copy_value(%@,%@)", appID, domain, key);
    return retval;
}

#pragma mark lockdown_set_value
static LockdownError (*original_lockdown_set_value)(LockdownConnectionRef connection, CFStringRef domain, CFStringRef key, CFPropertyListRef newValue);
static LockdownError replaced_lockdown_set_value(LockdownConnectionRef connection, CFStringRef domain, CFStringRef key, CFPropertyListRef newValue)
{
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    LockdownError retval = original_lockdown_set_value(connection, domain, key, newValue);
    if (appID) SSKLog(@"%@ lockdown_set_value(%@,%@)", appID, domain, key);
    return retval;
}
*/
/*
#pragma mark IOHIDDeviceGetProperty

extern CFTypeRef IOHIDDeviceGetProperty(IOHIDDeviceRef device, CFStringRef key);
static CFTypeRef (*original_IOHIDDeviceGetProperty)(IOHIDDeviceRef device, CFStringRef key);
static CFTypeRef replaced_IOHIDDeviceGetProperty(IOHIDDeviceRef device, CFStringRef key) {
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	if (appID) SSKLog(@"%@: IOHIDDeviceGetProperty(%@)", appID, key);
	CFTypeRef retval = original_IOHIDDeviceGetProperty(device, key);
	return retval;
}

#pragma mark cchmac_init

extern void cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t hc, unsigned long key_len, const void *key_data);

static void (*original_cchmac_init)(const struct ccdigest_info *di, cchmac_ctx_t hc, unsigned long key_len, const void *key_data);
static void replaced_cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t hc, unsigned long key_len, const void *key_data) {
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	writeAsHexToFile(appID, @"init", (unsigned char *)key_data, key_len);
	return original_cchmac_init(di, hc, key_len, key_data);
}

#pragma mark cchmac_update

extern void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc, size_t data_len, const void *data);

static void (*original_cchmac_update)(const struct ccdigest_info *di, cchmac_ctx_t hc, size_t data_len, const void *data);
static void replaced_cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t hc, size_t data_len, const void *data) {
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	writeDataToFile(appID, @"hmupdate", data, data_len, 0);
	return original_cchmac_update(di, hc, data_len, data);
}

#pragma mark ccdigest_update

extern void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);
static void (*original_ccdigest_update)(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data);
static void replaced_ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx, size_t len, const void *data) {
        NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	writeDataToFile(appID, @"dupdate", data, len, 0);
	return original_ccdigest_update(di, ctx, len, data);
}

#pragma mark ccdigest_init

extern void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
static void (*original_ccdigest_init)(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
static void replaced_ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx) {
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
	original_ccdigest_init(di, ctx);
	writeDataToFile(appID, @"dupdate", NULL, 0, di->output_size);
	return;
}
*/
/*
#pragma mark CC_SHA1 Hook

static unsigned char* (*original_CC_SHA1)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *replaced_CC_SHA1(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *retval = original_CC_SHA1(data, len, md);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    if (strstr(data, "__TEXT") == NULL) writeDataToFile(appID, data, len);
    return retval;
}

#pragma mark CC_SHA1_Update Hook

static int (*original_CC_SHA1_Update)(CC_SHA1_CTX *c, const void *data, CC_LONG len);
static int replaced_CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len) {
    int retval = original_CC_SHA1_Update(c, data, len);
    //NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    //if (strstr(data, "__TEXT") == NULL) writeDataToFile(appID, data, len);
    return retval;
}

#pragma mark CC_SHA256_Update Hook

static int (*original_CC_SHA256_Update)(CC_SHA256_CTX *c, const void *data, CC_LONG len);
static int replaced_CC_SHA256_Update(CC_SHA256_CTX *c, const void *data, CC_LONG len) {
    int retval = original_CC_SHA256_Update(c, data, len);
    //NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    //if (strstr(data, "__TEXT") == NULL) writeDataToFile(appID, data, len);
    return retval;
}

#pragma mark CC_SHA1_Final Hook

static int (*original_CC_SHA1_Final)(unsigned char *md, CC_SHA1_CTX *c);
static int replaced_CC_SHA1_Final(unsigned char *md, CC_SHA1_CTX *c) {
    int retval = original_CC_SHA1_Final(md, c);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    //writeDataToFile(appID, md, 20);
    writeAsHexToFile(appID, md, 20);
    return retval;
}

#pragma mark CC_SHA256_Final Hook

static int (*original_CC_SHA256_Final)(unsigned char *md, CC_SHA1_CTX *c);
static int replaced_CC_SHA256_Final(unsigned char *md, CC_SHA1_CTX *c) {
    int retval = original_CC_SHA256_Final(md, c);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    //writeDataToFile(appID, md, 32);
    writeAsHexToFile(appID, md, 32);
    return retval;
}
*/
/*
#pragma mark CC_SHA256 Hook

static unsigned char* (*original_CC_SHA256)(const void *data, CC_LONG len, unsigned char *md);
static unsigned char *replaced_CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    unsigned char *retval = original_CC_SHA256(data, len, md);
    NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
    if (strstr(data, "__TEXT") == NULL) writeDataToFile(appID, data, len);
    return retval;
}
*/

#pragma mark SSLSetSessionOption Hook

static OSStatus (*original_SSLSetSessionOption)(SSLContextRef context, SSLSessionOption option, Boolean value);
static OSStatus replaced_SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value)
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
    NSString *propstr = [NSString stringWithFormat:@"%@", (NSString*)prop];
    retval = orig_MGCopyAnswer(prop);

    if ([propstr isEqualToString:@"SerialNumber"] && nSerialNumber != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nSerialNumber);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nSerialNumber copy];
    } else if ([propstr isEqualToString:@"ProductType"] && nProductType != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nProductType);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nProductType copy];
    } else if ([propstr isEqualToString:@"ModelNumber"] && nModelNumber != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nModelNumber);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nModelNumber copy];
    } else if ([propstr isEqualToString:@"DeviceColor"] && nDeviceColor != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nDeviceColor);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nDeviceColor copy];
    } else if ([propstr isEqualToString:@"DeviceEnclosureColor"] && nDeviceEnclosureColor != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nDeviceEnclosureColor);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nDeviceEnclosureColor copy];
    } else if ([propstr isEqualToString:@"UniqueDeviceID"] && nUniqueDeviceID != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nUniqueDeviceID);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nUniqueDeviceID copy];
    } else if ([propstr isEqualToString:@"WifiAddress"] && nWifiAddress != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nWifiAddress);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nWifiAddress copy]; //[[NSString alloc]initWithString:nWifiAddress];
    } else if ([propstr isEqualToString:@"HWModelStr"] && nHWModelStr != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nHWModelStr);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nHWModelStr copy]; //[[NSString alloc]initWithString:nHWModelStr];
    } else if ([propstr isEqualToString:@"HardwarePlatform"] && nHardwarePlatform != nil) {
        SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nHardwarePlatform);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nHardwarePlatform copy]; //[[NSString alloc]initWithString:nHardwarePlatform];
    } else if ([propstr isEqualToString:@"BluetoothAddress"] && nBluetoothAddress != nil) {
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nBluetoothAddress);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [[NSString alloc]initWithString:nBluetoothAddress];
    } else if ([propstr isEqualToString:@"EthernetMacAddress"] && nEthernetMacAddress != nil) {
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nEthernetMacAddress);
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nEthernetMacAddress copy]; //[[NSString alloc]initWithString:nEthernetMacAddress];
    } else if ([propstr isEqualToString:@"UniqueChipID"] && nUniqueChipID != nil) {
        if (retval) CFRelease(retval);
		retval = (CFNumberRef) [nUniqueChipID copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nUniqueChipID);
    } else if ([propstr isEqualToString:@"DieId"] && nDieId != nil) {
		if (retval) CFRelease(retval);
		retval = (CFNumberRef) [nDieId copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nDieId);
    } else if ([propstr isEqualToString:@"MLBSerialNumber"] && nMLBSerialNumber != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nMLBSerialNumber copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nMLBSerialNumber);
    } else if ([propstr isEqualToString:@"FirmwareVersion"] && nFirmwareVersion != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nFirmwareVersion copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nFirmwareVersion);
    } else if ([propstr isEqualToString:@"CPUArchitecture"] && nCPUArchitecture != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nCPUArchitecture copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nCPUArchitecture);
    } else if ([propstr isEqualToString:@"WirelessBoardSnum"] && nWirelessBoardSnum != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nWirelessBoardSnum copy];
    } /*else if ([propstr isEqualToString:@"BasebandCertId"] && nBasebandCertId != nil) {
        if (retval) CFRelease(retval);
		retval = (CFNumberRef) [nBasebandCertId copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nBasebandCertId);
    } else if ([propstr isEqualToString:@"BasebandChipID"] && nBasebandChipId != nil) {
        if (retval) CFRelease(retval);
		retval = (CFNumberRef) [nBasebandChipId copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nBasebandChipId);
    } *//*else if ([propstr isEqualToString:@"BasebandFirmwareVersion"] && nBasebandFirmwareVersion != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [[NSString alloc]initWithString:nBasebandFirmwareVersion];
    } else if ([propstr isEqualToString:@"BasebandVersion"] && nBasebandVersion != nil) {
        if (retval) CFRelease(retval);
		retval = (CFStringRef) [nBasebandVersion copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nBasebandVersion);
    } */ else if ([propstr isEqualToString:@"InternationalMobileEquipmentIdentity"] && nInternationalMobileEquipmentIdentity != nil) {
        	if (retval) CFRelease(retval);
		retval = (CFStringRef) [nInternationalMobileEquipmentIdentity copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nInternationalMobileEquipmentIdentity);
    } /*else if ([propstr isEqualToString:@"MobileEquipmentIdentifier"] && nMobileEquipmentIdentifier != nil) {
        	if (retval) CFRelease(retval);
		retval = (CFStringRef) [nMobileEquipmentIdentifier copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nMobileEquipmentIdentifier);
    } */ else if ([propstr isEqualToString:@"BasebandPostponementStatusBlob"]) {
		CFIndex cnt = CFDictionaryGetCount((CFDictionaryRef)retval);
		CFMutableDictionaryRef newdict = CFDictionaryCreateMutableCopy(NULL, cnt, (CFDictionaryRef)retval);
		if (retval) CFRelease(retval);
		if (nInternationalMobileEquipmentIdentity != nil) {
			CFDictionaryReplaceValue(newdict, CFSTR("kCTPostponementInfoUniqueID"), (CFStringRef) [nInternationalMobileEquipmentIdentity copy]);
			CFDictionaryReplaceValue(newdict, CFSTR("InternationalMobileEquipmentIdentity"), (CFStringRef) [nInternationalMobileEquipmentIdentity copy]);
		}
		/*
		if (nMobileEquipmentIdentifier != nil) {
			CFDictionaryAddValue(newdict, CFSTR("MobileEquipmentIdentifier"), (CFStringRef) [nMobileEquipmentIdentifier copy]);
		}
		if (nBasebandChipId != nil) {
			CFDictionaryReplaceValue(newdict, CFSTR("BasebandChipID"), (CFNumberRef) [nBasebandChipId copy]);
		}*/
		if (nIntegratedCircuitCardIdentity != nil) {
			CFDictionaryAddValue(newdict, CFSTR("IntegratedCircuitCardIdentity"), (CFStringRef) [nIntegratedCircuitCardIdentity copy]);
		}
		//CFDictionaryReplaceValue(newdict, CFSTR("BasebandMasterKeyHash"), (CFStringRef) [nBasebandMasterKeyHash copy]);
		retval = newdict;
    } /*else if ([propstr isEqualToString:@"BasebandSecurityInfoBlob"]) {
		CFIndex cnt = CFDictionaryGetCount((CFDictionaryRef)retval);
		CFMutableDictionaryRef newdict = CFDictionaryCreateMutableCopy(NULL, cnt, (CFDictionaryRef)retval);
		if (retval) CFRelease(retval);
		CFDictionaryReplaceValue(newdict, CFSTR("CertID"), (CFNumberRef) [nBasebandCertId copy]);
		CFDictionaryReplaceValue(newdict, CFSTR("ChipID"), (CFNumberRef) [nBasebandChipId copy]);
		retval = newdict;
    } */ else if ([propstr isEqualToString:@"UniqueDeviceIDData"] && nUniqueDeviceIDData != nil) {
        if (retval) CFRelease(retval);
		retval = (CFDataRef) [nUniqueDeviceIDData copy];
		SSKLog(@"MGCopyAnswer(%@): %@\n", prop, nUniqueDeviceIDData);
    } else if ([propstr isEqualToString:@"CarrierBundleInfoArray"] && nCarrierBundleInfoArray != nil) {
        if (retval) CFRelease(retval);
	retval = (CFArrayRef) [nCarrierBundleInfoArray copy];
	SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nCarrierBundleInfoArray);
    } else if ([propstr isEqualToString:@"IntegratedCircuitCardIdentity"] && nIntegratedCircuitCardIdentity != nil) {
        if (retval) CFRelease(retval);
	retval = (CFStringRef) [nIntegratedCircuitCardIdentity copy];
	SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nIntegratedCircuitCardIdentity);

    } /*else if ([propstr isEqualToString:@"BoardId"] && nBoardId != nil) {
        if (retval) CFRelease(retval);
		retval = (CFNumberRef) [nBoardId copy];
		SSKLog(@"MGCopyAnswer(%@): replaced with %@\n", prop, nBoardId);
	}*/

    if (![propstr isEqualToString:@"ReleaseType"]) {
        SSKLog(@"MGCopyAnswer(%@)=%@\n", prop, retval);
    }

    return retval;
}

/*
typedef struct CTResult {
    int flag;
    int a;
} CTResult;

typedef const struct __CTServerConnection * CTServerConnectionRef;


extern void _CTServerConnectionCopyMobileEquipmentInfo(CTResult *status, CTServerConnectionRef connection, CFMutableDictionaryRef *equipmentInfo);
static void (*orig_CTServerConnectionCopyMobileEquipmentInfo)(CTResult *status, CTServerConnectionRef connection, CFMutableDictionaryRef *equipmentInfo);
static void replaced_CTServerConnectionCopyMobileEquipmentInfo(CTResult *status, CTServerConnectionRef connection, CFMutableDictionaryRef *equipmentInfo)
{
	orig_CTServerConnectionCopyMobileEquipmentInfo(status, connection, equipmentInfo);
    SSKLog(@"CTServerConnectionCopyMobileEquipmentInfo()=%@\n", equipmentInfo);
}
*/

static Boolean (*orig_MGGetBoolAnswer)(CFStringRef property);
static Boolean replaced_MGGetBoolAnswer(CFStringRef property)
{
    Boolean retval = orig_MGGetBoolAnswer(property);
    //SSKLog(@"MGGetBoolAnswer(%@)\n", property);
    //if (property == CFSTR("InternalBuild")) return true;
    //else if (property == CFSTR("Oji6HRoPi7rH7HPdWVakuw")) return true;
    return retval;
}

/*
#pragma mark SSLCopyPeerTrust hook
static OSStatus (*original_SSLCopyPeerTrust)(SSLContextRef context, SecTrustRef *trust);
static OSStatus replaced_SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust)
{
    OSStatus status = original_SSLCopyPeerTrust(context, trust);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}

#pragma mark SecTrustSetPolicies hook
static OSStatus (*original_SecTrustSetPolicies)(SecTrustRef trust, CFTypeRef policies);
static OSStatus replaced_SecTrustSetPolicies(SecTrustRef trust, CFTypeRef policies)
{
    OSStatus status = original_SecTrustSetPolicies(trust, policies);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}

static OSStatus (*original_SecTrustCreateWithCertificates)(CFTypeRef certificates, CFTypeRef policies, SecTrustRef *trust);
static OSStatus replaced_SecTrustCreateWithCertificates(CFTypeRef certificates, CFTypeRef policies, SecTrustRef *trust)
{
    OSStatus status = original_SecTrustCreateWithCertificates(certificates, policies, trust);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}


#pragma mark SecTrustCopyPublicKey hook
static SecKeyRef (*original_SecTrustCopyPublicKey)(SecTrustRef trust);
static SecKeyRef replaced_SecTrustCopyPublicKey(SecTrustRef trust)
{
    SecKeyRef keyref = original_SecTrustCopyPublicKey(trust);
    SSKLog(@"%s", __FUNCTION__);
    return keyref;
}

static OSStatus (*original_SecKeyRawVerify)(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen);
static OSStatus replaced_SecKeyRawVerify(SecKeyRef key, SecPadding padding, const uint8_t *signedData, size_t signedDataLen, const uint8_t *sig, size_t sigLen)
{
    OSStatus status = original_SecKeyRawVerify(key, padding, signedData, signedDataLen, sig, sigLen);
    SSKLog(@"%s", __FUNCTION__);
    return status;
}
*/

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
	NSString *appID = [[NSBundle mainBundle] bundleIdentifier];

        // SecureTransport hooks
        MSHookFunction((void *) SSLHandshake,(void *)  replaced_SSLHandshake, (void **) &original_SSLHandshake);
        MSHookFunction((void *) SSLSetSessionOption,(void *)  replaced_SSLSetSessionOption, (void **) &original_SSLSetSessionOption);
        MSHookFunction((void *) SSLCreateContext,(void *)  replaced_SSLCreateContext, (void **) &original_SSLCreateContext);
        //MSHookFunction((void *) SSLRead,(void *)  replaced_SSLRead, (void **) &original_SSLRead);
        //MSHookFunction((void *) SSLWrite,(void *)  replaced_SSLWrite, (void **) &original_SSLWrite);
        //MSHookFunction((void *) CFReadStreamCreateForHTTPRequest,(void *)  replaced_CFReadStreamCreateForHTTPRequest, (void **) &original_CFReadStreamCreateForHTTPRequest);
        //MSHookFunction((void *) CFHTTPMessageCreateRequest,(void *)  replaced_CFHTTPMessageCreateRequest, (void **) &original_CFHTTPMessageCreateRequest);
        //MSHookFunction((void *) CFHTTPMessageSetBody,(void *)  replaced_CFHTTPMessageSetBody, (void **) &original_CFHTTPMessageSetBody);
        MSHookFunction((void *) SecTrustEvaluate,(void *)  replaced_SecTrustEvaluate, (void **) &original_SecTrustEvaluate);
        //MSHookFunction((void *) lockdown_copy_value,(void *)  replaced_lockdown_copy_value, (void **) &original_lockdown_copy_value);
        //MSHookFunction((void *) lockdown_set_value,(void *)  replaced_lockdown_set_value, (void **) &original_lockdown_set_value);

	//MSHookFunction((void *) SecPolicyCreateSSL,(void *)  replaced_SecPolicyCreateSSL, (void **) &original_SecPolicyCreateSSL);
/*
	MSHookFunction((void *) cchmac_init,(void *)  replaced_cchmac_init, (void **) &original_cchmac_init);
	MSHookFunction((void *) cchmac_update,(void *)  replaced_cchmac_update, (void **) &original_cchmac_update);
        MSHookFunction((void *) ccdigest_update,(void *)  replaced_ccdigest_update, (void **) &original_ccdigest_update);
	MSHookFunction((void *) ccdigest_init,(void *)  replaced_ccdigest_init, (void **) &original_ccdigest_init);
	MSHookFunction((void *) IOHIDDeviceGetProperty, (void *)  replaced_IOHIDDeviceGetProperty, (void **) &original_IOHIDDeviceGetProperty);
*/
	//MSHookFunction((void *) CC_SHA1,(void *)  replaced_CC_SHA1, (void **) &original_CC_SHA1);
	//MSHookFunction((void *) CC_SHA1_Update,(void *)  replaced_CC_SHA1_Update, (void **) &original_CC_SHA1_Update);
	//MSHookFunction((void *) CC_SHA1_Final,(void *)  replaced_CC_SHA1_Final, (void **) &original_CC_SHA1_Final);
	//MSHookFunction((void *) CC_SHA256,(void *)  replaced_CC_SHA256, (void **) &original_CC_SHA256);
	//MSHookFunction((void *) CC_SHA256_Update,(void *)  replaced_CC_SHA256_Update, (void **) &original_CC_SHA256_Update);
	//MSHookFunction((void *) CC_SHA256_Final,(void *)  replaced_CC_SHA256_Final, (void **) &original_CC_SHA256_Final);

        //NSString *appID = [[NSBundle mainBundle] bundleIdentifier];
        // Substrate-based hooking; only hook if the preference file says so
	//if (appID && ([appID isEqualToString:@"com.apple.apsd"] || [appID isEqualToString:@"com.apple.lockdownd"] || [appID isEqualToString:@"com.apple.Preferences"])) {
	  if (appID && !([appID isEqualToString:@"com.apple.lockdownd"])) MSHookFunction((void *) SSLWrite,(void *)  replaced_SSLWrite, (void **) &original_SSLWrite);
/*
	    MSHookFunction((void *) SSLCopyPeerTrust,(void *)  replaced_SSLCopyPeerTrust, (void **) &original_SSLCopyPeerTrust);
            MSHookFunction((void *) SecTrustSetPolicies,(void *)  replaced_SecTrustSetPolicies, (void **) &original_SecTrustSetPolicies);
            MSHookFunction((void *) SecTrustCopyPublicKey,(void *)  replaced_SecTrustCopyPublicKey, (void **) &original_SecTrustCopyPublicKey);
            MSHookFunction((void *) SecTrustCreateWithCertificates,(void *)  replaced_SecTrustCreateWithCertificates, (void **) &original_SecTrustCreateWithCertificates);
            MSHookFunction((void *) SecKeyRawVerify,(void *)  replaced_SecKeyRawVerify, (void **) &original_SecKeyRawVerify);
*/
	    MSHookFunction((void*)MGGetBoolAnswer, (void*)replaced_MGGetBoolAnswer, (void**)&orig_MGGetBoolAnswer);
            MSHookFunction((void*)MGCopyAnswer, (void*)new_MGCopyAnswer, (void**)&orig_MGCopyAnswer);
            /*
            //if (appID && [appID isEqualToString:@"com.apple.Preferences"]) {
            //MSHookFunction((void*)_CTServerConnectionCopyMobileEquipmentInfo, (void*)replaced_CTServerConnectionCopyMobileEquipmentInfo, (void**)&orig_CTServerConnectionCopyMobileEquipmentInfo);
            //}
            //MSHookFunction((void*)MGGetBoolAnswer, (void*)replaced_MGGetBoolAnswer, (void**)&orig_MGGetBoolAnswer);
            oBuildVersion = (__bridge NSString *)orig_MGCopyAnswer(kMGBuildVersion);
            //SSKLog(@"oBuildVersion=%@", oBuildVersion);
            oDeviceColor = (__bridge NSString *)orig_MGCopyAnswer(kMGDeviceColor);
            //SSKLog(@"oDeviceColor=%@", oDeviceColor);
            oDeviceEnclosureColor = (__bridge NSString *)orig_MGCopyAnswer(CFSTR("DeviceEnclosureColor"));
            //SSKLog(@"oDeviceEnclosureColor=%@", oDeviceEnclosureColor);
            oHardwareModel = (__bridge NSString *)orig_MGCopyAnswer(kMGHWModel);
            //SSKLog(@"oHardwareModel=%@", oHardwareModel);
            oModelNumber = (__bridge NSString *)orig_MGCopyAnswer(kMGModelNumber);
            //SSKLog(@"oModelNumber=%@", oModelNumber);
            oProductType = (__bridge NSString *)orig_MGCopyAnswer(kMGProductType);
            //SSKLog(@"oProductType=%@", oProductType);
            oProductVersion = (__bridge NSString *)orig_MGCopyAnswer(kMGProductVersion);
            //SSKLog(@"oProductVersion=%@", oProductVersion);
            oSerialNumber = (__bridge NSString *)orig_MGCopyAnswer(kMGSerialNumber);
            //SSKLog(@"oSerialNumber=%@", oSerialNumber);
            oUniqueDeviceID = (__bridge NSString *)orig_MGCopyAnswer(kMGUniqueDeviceID);
            //SSKLog(@"oUniqueDeviceID=%@", oUniqueDeviceID);
            oWifiAddress = (__bridge NSString *)orig_MGCopyAnswer(kMGWifiAddress);
            //SSKLog(@"oWifiAddress=%@", oWifiAddress);
            oDieId = (__bridge NSNumber *)orig_MGCopyAnswer(kMGDieID);
            //SSKLog(@"oDieID=%@", oDieID);
            oHWModelStr = (__bridge NSString *)orig_MGCopyAnswer(CFSTR("HWModelStr"));
            oHardwarePlatform = (__bridge NSString *)orig_MGCopyAnswer(kMGHardwarePlatform);
            oBluetoothAddress = (__bridge NSString *)orig_MGCopyAnswer(kMGBluetoothAddress);
            oEthernetMacAddress = (__bridge NSString *)orig_MGCopyAnswer(CFSTR("EthernetMacAddress"));
            oUniqueChipID = (__bridge NSNumber *)orig_MGCopyAnswer(kMGUniqueChipID);
            oMLBSerialNumber = (__bridge NSString *)orig_MGCopyAnswer(kMGMLBSerialNumber);
            oFirmwareVersion = (__bridge NSString *)orig_MGCopyAnswer(kMGFirmwareVersion);
            oCPUArchitecture = (__bridge NSString *)orig_MGCopyAnswer(kMGCPUArchitecture);
            oWirelessBoardSnum = (__bridge NSString *)orig_MGCopyAnswer(CFSTR("WirelessBoardSnum"));
            oBasebandCertId = (__bridge NSNumber *)orig_MGCopyAnswer(kMGBasebandCertId);
            oBasebandFirmwareVersion = (__bridge NSString *)orig_MGCopyAnswer(kMGBasebandFirmwareVersion);
            oInternationalMobileEquipmentIdentity = (__bridge NSNumber *)orig_MGCopyAnswer(kMGInternationalMobileEquipmentIdentity);
			oMobileEquipmentIdentifier = (__bridge NSNumber *)orig_MGCopyAnswer(CFSTR("MobileEquipmentIdentifier"));
			*/
        //}
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

