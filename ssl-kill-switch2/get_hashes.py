#!/usr/bin/python
import sys
import os
import hashlib

if sys.argv[1:]:
    filename = sys.argv[1]
else:
    print("Usage: %s <filename>" % sys.argv[0])
    exit(0)

hashes = []
if os.path.isdir(filename):
    for filestr in os.listdir(filename):
        pathstr = os.path.join(filename, filestr)
        print("Opening %s" % pathstr)
        data=open(pathstr, 'rb').read()
        parts = data.split('\n')
        for i in range(0,len(parts)):
            if parts[i].startswith("SHA") == False: continue
            if parts[i+1].isdigit() and  len(parts[i+2]) == int(parts[i+1]):
                if parts[i+2].startswith("MGCopy"): continue
                if parts[i].startswith("SHA160"):
                    hashstr=hashlib.sha1(parts[i+2]).hexdigest()
                    if hashstr not in hashes: hashes.append(hashstr)
                elif parts[i].startswith("SHA256"):
                    hashstr=hashlib.sha256(parts[i+2]).hexdigest()
                    if hashstr not in hashes: hashes.append(hashstr)
                elif parts[i].startswith("SHA384"):
                    hashstr=hashlib.sha384(parts[i+2]).hexdigest()
                    if hashstr not in hashes: hashes.append(hashstr)
                elif parts[i].startswith("SHA384"):
                    hashstr=hashlib.sha512(parts[i+2]).hexdigest()
                    if hashstr not in hashes: hashes.append(hashstr)

hashes.sort()
for hashstr in hashes:
    print(hashstr)
