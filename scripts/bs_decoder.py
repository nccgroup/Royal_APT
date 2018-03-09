#!python2
__author__  = "Ahmed Zaki"
__date__ = "August 2017"


import logging
import sys
import os
import binascii
import re
import argparse
import base64


from Crypto.Cipher import AES


logger = logging.getLogger('BS2005 decoder')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('BS2005.log')
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)

# This decoder is based on the samples NCC group has observed,
# particularly the markers. 

START_MARKER="g00g1e"
END_MARKER="@2wp8h\)"

def decrypt(data):
	"""
		Takes a data blob and returns the decrypted data
	"""
	try:

		decodedData = base64.b64decode(data)
	
	except TypeError as e:
		logger.error("Could not base64 decode the data: %s", data)
		return None
	logger.debug("Decrypting...")
	key = decodedData[:16]
	logger.debug("Key: %s", binascii.hexlify(key))
	iv = decodedData[-16:]
	logger.debug("IV: %s", binascii.hexlify(iv))
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, IV=iv)
	ciphertext = decodedData[16:-16]
	try:
		plaintext = decryptor.decrypt(ciphertext)
	except ValueError as e:
		logger.error("Failed to decrypt %r - %s", ciphertext, e)
		return None
	return plaintext
		

def parsehtmlfile(htmlFile):
	"""
		Given a path to a BS2005 html file return the decoded command
	"""
	with open(htmlFile, 'rb') as fh:
		htmlData = fh.read()
		re_exp = START_MARKER+'.+'+END_MARKER
		regex = re.compile(re_exp)
		match = regex.search(htmlData)
		if match:
			command = match.group()
			pattern = START_MARKER+'|'+END_MARKER
			encodedCommand = re.sub(pattern, '', command)
			logger.debug("Extracted encoded C2 command: %s", encodedCommand)
			return encodedCommand

def main():
	parser = argparse.ArgumentParser(description="BS2005 decoder")
	parser.add_argument('type', choices=['html', 'beacon'])
	parser.add_argument('file', help="HTML File/Directory that includes the values to parse or string in the case of a beacon")
	options = parser.parse_args()
	if options.type == "html":
		
		dirFlag = False
		htmlFpath = os.path.abspath(options.file)

		if os.path.isdir(htmlFpath):
			dirFlag = True
			encodedDataList = []
			for _,_, filelist in os.walk(htmlFpath):
				for hFile in filelist:
					if hFile.endswith('htm'):
						hFilePath = os.path.join(htmlFpath, hFile)
						tDict = {"FileName": hFile, "EncodedData": parsehtmlfile(os.path.abspath(hFilePath))}
						encodedDataList.append(tDict)
		elif os.path.isfile(htmlFpath):
			encodedData = parsehtmlfile(htmlFpath)

		if dirFlag:
			for encodedDataDict in encodedDataList:
				if encodedDataDict['EncodedData']:
					output = decrypt(encodedDataDict['EncodedData'])
					logger.info("Data from file %s decoded to: %r", encodedDataDict['FileName'], output)
		else:
			logger.info("Decrypted Data: %r", decrypt(encodedData))
	
	elif options.type == "beacon":
		logger.info("Decrypted Data: %r", decrypt(options.file))

if __name__ == '__main__':
	main()