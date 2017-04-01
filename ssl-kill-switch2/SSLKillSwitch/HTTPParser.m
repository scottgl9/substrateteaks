#import "HTTPParser.h"

NSString* isHTTPRequest(NSData *data)
{
    NSString* datastr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    
    if ([datastr hasPrefix:@"GET"] || [datastr hasPrefix: @"POST"] || [datastr hasPrefix: @"PUT"]) {
        return datastr;
    }

    return NULL;
}


NSString* getHttpRequestCommand(NSString *data)
{
    NSUInteger index = [data rangeOfString:@"\r\n"].location;
    NSString *command = [data substringWithRange:NSMakeRange(0, index)];
    
    return command;
}

NSArray* getHttpRequestHeaders(NSString *data)
{
    NSUInteger index = [data rangeOfString:@"\r\n\r\n"].location;
    NSString *header = [data substringWithRange:NSMakeRange(0, index)];
    
    NSArray *headers =  [header componentsSeparatedByCharactersInSet:
                        [NSCharacterSet characterSetWithCharactersInString:@"\r\n"]
                        ];
    return headers;
}

NSString* getHttpRequestBody(NSString *data)
{
    NSUInteger index = [data rangeOfString:@"\r\n\r\n"].location;
    NSString *body = [data substringWithRange:NSMakeRange(index, data.length)];
    return body;
}

int HttpRequestReplaceString(void *data, size_t len, char *s1, char *s2)
{
    if (!len) return 0;
    char *origptr = strstr((char *)data, s1);
    if (!origptr) return 0;
    if (strlen(s1) != strlen(s2)) return 0;
    memcpy(origptr, s2, strlen(s2));
    return 1;
}
