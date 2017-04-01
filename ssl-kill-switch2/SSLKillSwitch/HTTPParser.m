#import "HTTPParser.h"

NSString* isHTTPRequest(NSData *data)
{
    NSString* datastr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    if ([datastr hasPrefix:@"GET"] || [datastr hasPrefix: @"POST"] || [datastr hasPrefix: @"PUT"]) {
        return datastr;
    }

    return NULL;
}