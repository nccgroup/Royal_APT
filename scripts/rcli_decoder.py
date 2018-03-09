#!python2
__author__  = "Ahmed Zaki"
__date__ = "June 2017"

import os
import sys
import re
import binascii 
import logging 
import struct
import argparse
import base64
import string


# This decoder is based on the samples NCC group has observed,
# particularly the markers. 

HTML_HOST_MARKER = "(page|msec)"
HTML_KEY_MARKER = "(row|mkey)"

logger = logging.getLogger('RoyalCliDecoder')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('rcli_debug.log')
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)


class Decoder(object):

    def _round(self,x, y):
        """ 
            Perform one round of the key generation
        """
        temp = x+int(0x12345678)
        temp = temp ^ int(0x55AA9966)
        return (temp + y) & 0xffffffff
    
    def _decrypt(self,key1, key2, encData):
        """ 
            Perform decryption on Data given two keys
        """
        decryptionK = key1
        seedy = key2
        result = ''
        for byte in encData:
            t = self._round(decryptionK, seedy)
            temp= ord(byte)^ord(struct.pack('I', decryptionK)[0])
            result += chr(temp ^ ord(struct.pack('<I',t)[0]))
            seedy = decryptionK 
            decryptionK = t 
        
        return result

    def _generateKeys(self,data):
        """
            Generate Keys to be used for decryption
        """
        (dword1, dword2, dword3, dword4) = struct.unpack("<IIII", data)
        seedx = dword3^dword2
        seedy = dword4^dword1

        ## 8 rounds of generation for the key to be used
        for x in xrange(8):
            retval = self._round(seedx, seedy)
            seedy = seedx
            seedx = retval
        
        return retval, seedy
    
    def decode_params(self, data, key):
        """
            Given encoded data and a seed key, decode the data
        """
        logger.debug("Data to decrypt: %s", data)
        logger.debug("Key: %s", key)
        customcharset = "ABCDEFGHIJKLMNOP"
        stdcharset = "0123456789ABCDEF"
        m = key.translate(string.maketrans(customcharset, stdcharset))
        logger.debug("Keys IV stream: %r", binascii.hexlify(base64.b16decode(m)))
        key1, key2 = self._generateKeys(base64.b16decode(m))
        p = data.translate(string.maketrans(customcharset,stdcharset))
        result = self._decrypt(key1, key2, base64.b16decode(p)).strip('\x00')
        return  result
    
    def decode_html(self, fPath):
        """
            Given a path to a RoyalCLI html, return the decoded data
        """
        logger.info("[+] Decoding data in: %s",fPath)
        with open(fPath, 'r') as fh:
            data = fh.read()
            regex = re.compile('\\\\+.+\\\\+')
            dMatch = regex.match(data)
            regexHost = '{0}=[A-P]+'.format(HTML_HOST_MARKER)
            regexKey = '{0}=[A-P]+'.format(HTML_KEY_MARKER)
            encMachine = re.search(regexHost, data)
            encKey = re.search(regexKey, data)


        if dMatch:
            c2Data = dMatch.group()
            encBytes = c2Data.strip('\\')
        else:
            logger.error("[!] Could not find prepended data sequence\n")
            return None, None
        
        if encMachine:
            logger.debug("Encoded Host Name: %s", encMachine.group())
            encMachine = encMachine.group()
            subPattern = HTML_HOST_MARKER + '='
            encMachine = re.sub(subPattern, '', encMachine)
        
        if encKey:
            logger.debug("Encoded Key: %s", encKey.group())
            encKey = encKey.group()
            subPattern = HTML_KEY_MARKER + '='
            encKey = re.sub(subPattern, '', encKey)



        resArray = base64.b64decode(encBytes)
        key1, key2 = self._generateKeys(resArray[:16])

        return self.decode_params(encMachine, encKey), self._decrypt(key1, key2, resArray[16:])


        
    def decode_config(self, data):
        """ 
            This function will decode the config file. 
        """
        key1, key2 = self._generateKeys(data[:16])
        result = self._decrypt(key1, key2, data[16:])
        return result

    def write_to_file(self, outfile, data):
        with open(outfile, 'wb') as fh:
            fh.write(data)
        logger.info("[+] Output written to: %s", outfile)



parser = argparse.ArgumentParser()
parser.add_argument('type', choices=['html', 'cfg', 'uri'])
parser.add_argument('-d', '--dumptofile', action='store_true', help="Will write output to a file")
parser.add_argument('file', help="file|dir|string")
options = parser.parse_args()

dObj = Decoder()

if options.type == "html":
    fPath = os.path.abspath(options.file)
    if os.path.isdir(fPath):
        pDir = fPath
        # Get all files
        for cDir, dirName, files in os.walk(os.path.abspath(pDir)):
            for fileName in files:
                if fileName.endswith('.htm'):
                    logger.info("[+] Parsing html file: %s", fileName)
                    fileNamePath = os.path.join(cDir, fileName)
                    params, data = dObj.decode_html(os.path.abspath(fileNamePath))
                    if params and data:
                        if options.dumptofile:
                            decodedFileName = ".".join([fileName.strip(".htm"), "bin"])
                            fulldata = "\n".join([params, data])
                            dObj.write_to_file(decodedFileName, fulldata)
                        else:
                            logger.info("[+] Decoded MachineName: %r\n", params)
                            logger.info("[+] Decoded Data: %r\n", data)
               
    elif os.path.isfile(fPath):            
        params, data = dObj.decode_html(fPath)
        if options.dumptofile:
            fileName = os.path.basename(os.path.abspath(fPath))
            fileName = os.path.splitext(fileName)[0]
            decodedFileName = ".".join([fileName, "bin"])
            fulldata = "\n".join([params, data])
            dObj.write_to_file(decodedFileName, fulldata)
        else:
            logger.info("[+] Decoded Host Name: %r\n", params)
            logger.info("[+] Decoded Data: %r\n", data)
        
    else:
        logger.error("[!] Invalid argument. Please make sure you provide a valid dir or file")
        
elif options.type == "cfg":
    fPath = os.path.abspath(options.file)
    with open(fPath, 'rb') as oh:
        data = oh.read()
        result = dObj.decode_config(data)
    if options.dumptofile:
        decodedFileName = ".".join([os.path.splitext(fPath)[0], "bin"])
        dObj.write_to_file(decodedFileName, result)
    else:
        logger.info("[+] Decoded Config: %r\n", result)

elif options.type == "uri":
    inputData = options.file
    pattern = '.*{0}=(?P<data>[A-Z]+)&{1}=(?P<key>[A-Z]+)'.format(HTML_HOST_MARKER, HTML_KEY_MARKER)
    check = re.match(pattern, inputData)
    if check:
        data = check.group('data')
        key = check.group('key')
        result = dObj.decode_params(data, key)
        if options.dumptofile:
            dObj.write_to_file("decoded_uri.bin", result)
        else:
            logger.info("[+] Decoded Host Name: %r", result)