#!/usr/bin/python3

# Copyright 2012 Timmy Douglas

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
import getopt
import sys
import binascii
import socket
import hmac
import os
import io
import json

#from email.utils import formatdate
import datetime
from time import sleep

if sys.version < '3':
    from httplib import HTTPConnection
    from urlparse import urlparse, parse_qs
    import ConfigParser as configparser
else:
    import configparser
    from http.client import HTTPConnection
    from urllib.parse import urlparse, parse_qs


class Profile:

    def __init__(self, access_id='',key='',region="us-east-1",debug=False,log='~/.awslog',chunksize=4*2**20,maxtries=20,host="glacier.us-east-1.amazonaws.com",port=80):
        self.accessid = access_id
        self.key = key
        self.region = region
        self.debug = debug
        self.log = log
        self.chunksize = chunksize
        self.maxtries = maxtries
        self.host = host
        self.port = port
    
    def getAccessID(self):
        return self.accessid

    def getKey(self):
        return self.key

    def getRegion(self):
        return self.region

    def getDebug(self):
        return self.debug
    
    def getLog(self):
        return self.log

    def getChunksize(self):
        return self.chunksize

    def getMaxtries(self):
        return self.maxtries

    def getHost(self):
        return self.host

    def getPort(self):
        return self.port


def hashfile(filename, chunksize=2**20):
    with open(filename, 'rb') as infile:
        return hashstream(infile, chunksize)


def hashstream(infile, chunksize=2**20):
    h = hashlib.sha256()
    treehashlist = []
    while True:
        data = infile.read(chunksize)
        if len(data) == 0:
            break
        th = hashlib.sha256()
        th.update(data)
        treehashlist += [th.digest()]
        h.update(data)

    return h.digest(), treehash(treehashlist), treehashlist


def hashpair(x,y):
    h = hashlib.sha256()
    h.update(x)
    h.update(y)
    return h.digest()

def treehash(lines):
    if len(lines) == 0:
        return hashpair(b'',b'')
    while len(lines) > 1:
        lista = lines[::2]
        listb = lines[1::2]
        extra = []
        if len(lista) > len(listb):
            extra = [lista[-1]]
        pairs = zip(lista, listb)
        lines = [hashpair(x,y) for x,y in pairs] + extra
    return lines[0]
    
class RequestException(Exception):
    def __init__(self, message):
        Exception.__init__(self,message)


        
class Request():

    @staticmethod
    def HMAC(key,msg):
        hm = hmac.new(key, msg.encode('utf-8'), digestmod=hashlib.sha256)
        return hm.digest()

    @staticmethod
    def getBasicDateTime():
        return datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

    @staticmethod
    def getBasicDate():
        return datetime.datetime.utcnow().strftime('%Y%m%d')

    @staticmethod
    def hexhash(data):
        h = hashlib.sha256()
        h.update(data)
        return h.hexdigest()

    def __init__(self, profile, method, url):
        self.accessid = profile.getAccessID()
        self.accesskey = profile.getKey()
        self.region = profile.getRegion()
        self.debug = profile.getDebug()
        self.profile = profile
        self.hideResponseHeaders = not profile.getDebug() 
        self.method = method
        self.url = url
        self.headers = {}
        self.date = Request.getBasicDate()
        self.time = Request.getBasicDateTime()
        self.headers['Host'] = 'glacier.' + self.region + '.amazonaws.com'
        self.headers['x-amz-glacier-version'] = '2012-06-01'
        self.headers['x-amz-date'] = self.time
        #formatdate(timeval=None, localtime=False, usegmt=True)
        self.payload = b''

    def addContentLength(self):
        self.headers['Content-Length'] = str(len(self.payload))

    def getAuthType(self):
        return 'AWS4-HMAC-SHA256'

    def setPayloadFile(self, filename):
        with open(filename, 'rb') as fb:
            self.payload = fb.read()

        linearhash, treehash, thl = hashfile(filename)
        self.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
        self.headers['x-amz-content-sha256'] = binascii.hexlify(linearhash).decode('ascii')


    def setPayloadContents(self, payload):
        self.payload = payload
        linearhash, treehash, thl = hashstream(io.BytesIO(self.payload))
        self.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
        self.headers['x-amz-content-sha256'] = binascii.hexlify(linearhash).decode('ascii')



    def getStringToSign(self):
        s = self.getAuthType() + '\n'
        s += self.time + '\n'
        s += self.date + '/' + self.region + '/glacier/aws4_request' + '\n'
        s += Request.hexhash(self.getCanonicalString().encode('ascii'))
        if self.debug:
            print('===\nString to sign:\n' + s + '===')
        return s

    def getDerivedKey(self):
        if len(self.accesskey) == 0:
            raise ValueError('Access Key not specified. Use --key or edit your configuration file.')
        kDate = Request.HMAC(("AWS4" + self.accesskey).encode("utf-8"), self.date)
        kRegion = Request.HMAC(kDate, self.region)
        kService = Request.HMAC(kRegion, 'glacier')
        kSigning = Request.HMAC(kService, "aws4_request")
        return kSigning



    def getAuthorizationLine(self):
        #do this first because it creates signedheaders
        strtosign = self.getStringToSign()
        derivedkey = self.getDerivedKey()
        sig = Request.HMAC(derivedkey, strtosign)
        if len(self.accessid) == 0:
            raise ValueError('Access ID not specified. Use --id or edit your configuration file.')


        s = self.getAuthType() + ' Credential=' + self.accessid + '/' + self.date + '/' + self.region
        s += '/glacier/aws4_request,SignedHeaders=' + self.signedheaders
        s += ',Signature=' + binascii.hexlify(sig).decode('ascii')

        return s

    def sign(self):
        self.headers['Authorization'] = self.getAuthorizationLine()

    def getCanonicalString(self):
        urlparts = urlparse(self.url)
        querystring = parse_qs(urlparts.query)
        can_headers = {}
        ok_keys = ['content-sha256', 'content-type', 'date', 'host']

        for key in self.headers:
            lk = key.lower()
            if self.headers[key] is not None and (lk in ok_keys or lk.startswith('x-amz-')):
                can_headers[lk] = self.headers[key].strip()

        canquerystring = ''
        for key in sorted(querystring):
            val = querystring[key]
            canquerystring += '&' + key + '=' + val[0].strip() + '\n'

        if len(canquerystring) == 0:
            canquerystring = '\n'
        else:
            if (canquerystring[0] == '&'):
                canquerystring = canquerystring[1:]
            

        s = self.method + '\n'
        s += urlparts.path + '\n'
        s += canquerystring
        signedheaders = ''
        for key in sorted(can_headers.keys()):
            val = can_headers[key]
            s += key + ':' + val.strip() + '\n'
            signedheaders += key + ';'

        s += '\n' # end signed headers
        
        self.signedheaders = signedheaders[:-1]
        s += self.signedheaders + '\n'     # erase last ;


        s += Request.hexhash(self.payload)

        if self.debug:
            print("===\nCanonical Request: \n" + s + '===')

        return s

    def send(self, outfile=None):
        con = HTTPConnection(self.profile.getHost(), self.profile.getPort())
        con.set_debuglevel(self.profile.getDebug())
        con.request(self.method, self.url, self.payload, self.headers)


        res = con.getresponse()
        if not self.hideResponseHeaders:
            print("\n\nStatus: " + str(res.status))
            print("Reason: " + str(res.reason))
            print("Headers: " + str(res.getheaders()))
        
        reply = None
        if outfile == None:
            reply = res.read()
            if not self.hideResponseHeaders:
                print("Reply:\n" + str(reply))
        else:
            with open(outfile, 'wb') as of:
                while True:
                    x = res.read(4096)
                    if len(x) == 0:
                        break
                    of.write(x)

        con.close()
        if res.status != 200:
	    raise RequestException(res.reason)
        return res, reply



    def __str__(self):
        s = self.method + ' ' + self.url + ' HTTP/1.1\n'
        for key in self.headers.keys():
            val = self.headers[key]
            s += key + ': ' + val + '\n'

        s += '\n'

        return s
            
class Vault:
    def __init__(self,profile,vaultname,properties=None):
        self.vaultname = vaultname
        self.profile = profile
        if properties == None:
            res,reply = Vault.vaultoperation(self.profile, 'GET', self.vaultname)
            self.properties = json.loads(reply.decode('utf-8'))
        else:
            self.properties = properties




    @staticmethod
    def vaultoperation(profile, op, name):
        req = Request(profile, op, '/-/vaults/' + name)
        req.addContentLength()
        req.sign()
        return req.send()

    @staticmethod
    def create(profile,name):
        Vault.vaultoperation(profile, 'PUT', name)
        return Vault(profile,name)

    @staticmethod
    def getVaults(profile):
        req = Request(profile, 'GET', '/-/vaults')
        req.addContentLength()
        req.sign()
        res,reply = req.send()
        vaultinfo = json.loads(reply.decode('utf-8'))
        vaults = []
        if 'VaultList' in vaultinfo:
            for vault in vaultinfo['VaultList']:
                if 'VaultName' in vault:
                    vaults.append(Vault(profile,vault['VaultName'],vault))
        return vaults

    def getProperties(self):
    	return self.properties

    def delete(self):
        Vault.vaultoperation(self.profile, 'DELETE', self.vaultname)

    def __str__(self):
        return self.vaultname


class FileOps:

    @staticmethod
    def getPart(filename, offset, partsize):
        with open(filename, 'rb') as fb:
            fb.seek(offset)
            return fb.read(partsize)


class Archive:
    def __init__(self,profile,vault):
        self.profile = profile
        pass

    def upload(self, vault, filename, description=None):
        """ Single Request upload """
        req = Request(self.profile, 'POST', '/-/vaults/' + vault + '/archives')
        if description != None:
            req.headers['x-amz-archive-description'] = description

        req.setPayloadFile(filename)
        req.addContentLength()
        req.sign()
        req.send()

    def delete(config, vault, archiveid):
        req = Request(config, 'DELETE', '/-/vaults/' + vault + '/archives/' + archiveid)
        req.addContentLength()
        req.sign()
        req.send(config)
    
class Upload:
    def __init__(self,vault,multipart=False):
        self.uploadid = None
        self.vault = vault

    def listParts(config, vault, uploadid, marker=None):
        query = '/-/vaults/' + vault + '/multipart-uploads/' + uploadid
        if marker != None:
            query += '?marker=' + marker
        req = Request(config, 'GET', query)
        req.hideResponseHeaders = True
        req.addContentLength()
        req.sign()
        return req.send(config)

    def findUploadedOffset(config, vault, uploadid):
        parts = []
        marker = None
        while True:
            res, reply = listParts(config, vault, uploadid, marker)
            partreply = json.loads(reply.decode('utf-8'))
            if 'Parts' not in partreply:
                raise KeyError('Parts not in ' + str(partreply))
            parts += partreply['Parts']
            marker = partreply['Marker']
            if marker == None:
                break

        # TODO? verify the treehashes?
        maxoffset = 0
        for item in parts:
            maxval = int(item['RangeInBytes'].split('-')[1])
            maxoffset = max(maxoffset, maxval)
        return maxoffset, parts

    def treehashFromList(thl, start, end):
        start = start//1024//1024
        end = end//1024//1024
        hashparts = thl[start:end]
        return treehash(hashparts)

    def checkHashes(config, vault, filename, uploadid):
        offset, parts = findUploadedFileOffset(config, vault, uploadid)
        badhashes = []
        print("Hashing file: " + str(filename))
        fullhash, treehash, thl = hashfile(filename)
        for part in parts:
            rng = [int(x) for x in part['RangeInBytes'].split('-')]
            mytreehash = binascii.hexlify(treehashFromList(thl, rng[0], rng[1])).decode('ascii')
            # ??? aws puts '01' at the beginning of their hash?
            if mytreehash not in part['SHA256TreeHash']:
                badhashes += [part]
                print("Hash mismatch: " + str(part) + "\nExpected: " + str(mytreehash)
                      + "\nAt offset: " + str(rng[0]/1024/1024) + " MB to "
                      + str(rng[1]/1024/1024) + ' MB')
        print('Checked ' + str(len(parts)) + ' hashes')
        print('Full file hash: ' + binascii.hexlify(fullhash).decode('ascii'))
        print('Full file treehash: ' + binascii.hexlify(treehash).decode('ascii'))
        return badhashes
        
    def repairMultipart(config, vault, filename, uploadid, partsize=None):
        if partsize == None:
            partsize = self.profile.getChunksize()
        parts = checkHashes(config, vault, filename, uploadid)
        for part in parts:
            rng = [int(x) for x in part['RangeInBytes'].split('-')]
    
    
            offset = rng[0]
            part = getFilePart(filename, offset, partsize)

            # len(part) will work for chunks and the last chunk in the file rather than partsize
            if (rng[1] - rng[0] != len(part)):
                raise ValueError('Part size expected: ' + str(partsize) + ' found: ' + str(rng[1] - rng[0]))


            req = Request(config, 'PUT', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
            part = getFilePart(filename, offset, partsize)
            req.headers['Content-Range'] = 'bytes ' + str(offset) + '-' + str(offset+len(part)-1) + '/*'
            req.setPayloadContents(part)

            req.addContentLength()
            req.sign()
            #req.hideResponseHeaders = True
            res, reply = req.send(config)
            if res.status != 204:
                raise ValueError('Expected 204 response from multipart PUT request @ offset '
                                 + str(offset) + '\n' 
                                 + str(res.reason) + '\n' 
                                 + str(res.getheaders()) + '\n'
                                 + str(reply))
    
            print('Repaired part at offset ' + str(offset) + ' (' + str(offset//1024//1024) + ' MB)')



    def multipartUpload(config, vault, filename, description=None, uploadid=None, partsize=None,maxtries=None):
        if partsize == None:
            partsize = self.profile.getChunksize()
        if maxtries == None:
            maxtries = self.profile.getMaxtries()
    
        offset = 0
        size = os.stat(filename).st_size
    
        # uploadid is set to the multipart upload id or None if starting for the first time
        if uploadid == None:
            req = Request(config, 'POST', '/-/vaults/' + vault + '/multipart-uploads')
            if description != None:
                req.headers['x-amz-archive-description'] = description
            req.headers['x-amz-part-size'] = str(partsize)
    
            req.addContentLength()
            req.sign()
            req.hideResponseHeaders = True
            res, reply = req.send(config)
            uploadid = res.getheader('x-amz-multipart-upload-id')
            if not uploadid:
                raise KeyError('x-amz-multipart-upload-id not in response headers')
            print('Starting upload of ' + filename)
            print('Upload ID: ' + str(uploadid))
        else:
            uploadid = uploadid
            offset, parts = findUploadedFileOffset(config, vault, uploadid)
            print('Resuming upload at offset: ' + str(offset) + ' (' + str(offset//1024//1024) + ' MB)')
    

        while offset < size:
            req = Request(config, 'PUT', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
            part = getFilePart(filename, offset, partsize)
            req.headers['Content-Range'] = 'bytes ' + str(offset) + '-' + str(offset+len(part)-1) + '/*'
            req.setPayloadContents(part)

            req.addContentLength()
            req.sign()
            req.hideResponseHeaders = True
            try:
                res, reply = req.send(config)
                if res.status != 204:
                    print('Expected 204 response from multipart PUT request @ offset '
                          + str(offset) + '\n' 
                          + str(res.reason) + '\n'
                          + str(res.getheaders()) + '\n'
                          + str(reply))
                    maxtries -= 1
                    if maxtries < 1:
                        print('Try limit exceeded...exiting')
                        return
                    continue
    
    
                print('Uploaded ' + str(len(part)/1024/1024) + ' MB @ offset ' + str(offset) + ' bytes (' + str(offset//1024//1024) + ' MB)')
                offset += len(part)
            except socket.error as e:
                print('Socket error: ' + str(e))
                if maxtries < 1:
                    print('Try limit exceeded...exiting')
                    return
                print('Retrying...')
                sleep(1)
                maxtries -= 1
    
        print('Calculating hash and finishing upload of ' + filename)
        # calculate hash before creating the request otherwise it might be out of date by the time
        # we send the request
        linearhash, treehash, thl = hashfile(filename)
    
        req = Request(config, 'POST', '/-/vaults/' + vault + '/multipart-uploads/'+uploadid)
        req.headers['x-amz-archive-size'] = str(size)
        req.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
        req.addContentLength()
        req.sign()
        res, reply = req.send(config)
    
        print('Uploaded ' + filename)
        if res.status != 201:
            raise ValueError('Expected 201 Created response from upload finish request')
        if 'log' in config and len(config['log']) > 0:
            path = os.path.expanduser(config['log'])
            location = res.getheader('Location', uploadid)
            with open(path, 'a') as fd:
                fd.write(str(filename) + '->' + location + '\n')
                print('Wrote upload log entry to ' + path)
    
    
    def listUploads(config, vault):
        req = Request(config, 'GET', '/-/vaults/' + vault + '/multipart-uploads')
        req.addContentLength()
        req.sign()
        req.send(config)
    
    def abortUpload(config, vault, uploadid):
        req = Request(config, 'DELETE', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
        req.addContentLength()
        req.sign()
        req.send(config)
    
class Job:

    @staticmethod
    def createJob(config, vault, params):
        req = Request(config, 'POST', '/-/vaults/' + vault + '/jobs')
        req.setPayloadContents(json.dumps(params).encode('utf-8'))
        req.addContentLength()
        req.sign()
        req.send(config)
    
    @staticmethod
    def list(config, vault, joboutput=None):
        req = Request(config, 'GET', '/-/vaults/' + vault + '/jobs')
        req.addContentLength()
        req.sign()
        req.send(config, joboutput)
    
    def getJobOutput(config, vault, jobid, joboutput=None):
        req = Request(config, 'GET', '/-/vaults/' + vault + '/jobs/' + jobid + '/output')
        req.addContentLength()
        req.sign()
        req.send(config, joboutput)
    
