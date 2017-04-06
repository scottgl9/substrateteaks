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
	size_t s1len = strlen(s1);
	char *dataptr = (char *)data;
	size_t j = 0;
	int found=0;
	for(size_t i=0; i<len; i++)
	{
		if (dataptr[i] == s1[i]) {
			for (j=0; j < s1len; j++) if (s1[j] != dataptr[i+j]) break;
			if (j >= (s1len - 1)) {
				memcpy(dataptr, s2, s1len);
				found=1;
			}
		}
		dataptr++;
	}

    return found;
}
