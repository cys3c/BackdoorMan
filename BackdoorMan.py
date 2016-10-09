#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
released under the MIT License
MIT License

Copyright (c) 2016 Yassine Addi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

import os, sys, time, re, socket
from thirdparty import *
from datetime import datetime
from collections import defaultdict
from optparse import OptionParser

__version__ = '2.0.0'

class Man:
	def __init__(self, dest):
		self.dest = dest
		self.internet = self.Internet()
		self.shells = open('data/shells.txt', 'rb').read().split('\n')
		self.functions = '|'.join(open('data/functions.txt', 'rb').read().split('\n'))
		self.codes = '|'.join(open('data/codes.txt', 'rb').read().split('\n'))
		totalFiles = sum([len(files) for p, r, files in os.walk(dest)])
		started = datetime.now()
		print('Scanning: {} ({})'.format(dest, totalFiles))
		print('Started:  {}'.format(started))
		print('=' * 37 + '\n')
		extensions = defaultdict(int)
		for dirpath, dirnames, filenames in os.walk(dest):
			for filename in filenames:
				extensions[os.path.splitext(filename)[1].lower() if filename.lower() != '.htaccess' else 'htaccess'] += 1
		self.ReportParentInfo('Scanning: {}'.format(totalFiles))
		for key, value in extensions.items():
			self.ReportChildInfo('{}: {}'.format(key.strip('.').upper() if key.split() else 'Other', value))
		print('')
		self.Initiate()
		print('\n' + '=' * 37)
		ended = datetime.now()
		print('Ended:    {}'.format(ended))
		elapsed = ended - started
		elapsed = divmod(elapsed.days * 86400 + elapsed.seconds, 60)
		print('Elapsed:  {} Minutes, {} Seconds'.format(elapsed[0], elapsed[1]))

	def Initiate(self):
		for dirpath, dirnames, filenames in os.walk(self.dest):
		    for filename in filenames:
		    	file = os.path.join(dirpath, filename)
		    	if os.path.splitext(filename)[1].lower().strip(".") == "php":
		    		self.ScanPHPFile(file)

	def ScanPHPFile(self, file):
		filename = os.path.basename(file)
		for shell in self.shells:
			if shell in filename.lower():
				self.ReportParentRisk('Suspecious File Name: {}'.format(filename))
				for child in self.GetFileInfo(file):
					self.ReportChildRisk(child)
				print('')
		with open(file, 'rb') as f:
			for i, line in enumerate(f.read().split('\n')):
				result = re.findall(r'(?si)({})'.format(self.functions), line)
				if result:
					for term in result:
						self.ReportParentRisk('Suspicious Function: {}'.format(filename))
						self.ReportChildRisk('Function Name: {}'.format(term))
						self.ReportChildRisk('Line Number: {}'.format(i+1))
						for child in self.GetFileInfo(file):
							self.ReportChildRisk(child)
						print('')
				result = re.findall(r'(?si)({})'.format(self.codes), line)
				if result:
					for term in result:
						self.ReportParentRisk('Suspecious Code: {}'.format(filename))
						self.ReportChildRisk('PHP Code: {}'.format(term))
						self.ReportChildRisk('Line Number: {}'.format(i+1))
						for child in self.GetFileInfo(file):
							self.ReportChildRisk(child)
						print('')
			if self.Internet():
				res = ShellRay(open(file, 'r'))
				if res:
					self.ReportParentRisk('Malware Detected: {}'.format(filename))
					self.ReportChildRisk('Service Provider: ShellRay')
					self.ReportChildRisk('Threat Name: {}'.format(res['threatname']))
					self.ReportChildRisk('SHA1: {}'.format(res['sha1']))
					self.ReportChildRisk('MD5: {}'.format(res['md5']))
					for child in self.GetFileInfo(file):
						self.ReportChildRisk(child)
					print('')
				res = VirusTotal(open(file, 'r'))
				if res:
					results = [res["scans"][antivirus]["result"] for antivirus in res["scans"] if res["scans"][antivirus]["detected"]]
					self.ReportParentRisk('Malware Detected: {}'.format(filename))
					self.ReportChildRisk('Service Provider: VirusTotal')
					self.ReportChildRisk('Detection Ratio: {} / {}'.format(res['positives'], res['total']))
					self.ReportChildRisk('Results: {}'.format(', '.join(results)))
					for child in self.GetFileInfo(file):
						self.ReportChildRisk(child)
					print('')

	def GetFileInfo(self, file):
		(mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(file)
		return [
			"Full Path: {}".format(file),
			"Owner: {}".format((str)(uid) + ":" + str(gid)),
			"Permission: {}".format((oct)(mode)[-3:]),
			"Last Accessed: {}".format((time).ctime(atime)),
			"Last Modified: {}".format((time).ctime(mtime)),
			"File Size: {}".format((self).GetFileHumanSize(size))
		]

	def GetFileHumanSize(self, size, suffix='B'):
		for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
			if abs(size) < 1024.0:
				return "%3.1f%s%s" % (size, unit, suffix)
			size /= 1024.0
		return "%.1f%s%s" % (size, 'Yi', suffix)

	def Internet(self):
		try:
			host, _, addrList = socket.gethostbyaddr('216.58.192.142')
			s = socket.create_connection((addrList[0], 80), 2)
			return True
		except:
			return False

	def SupportsColor(self):
		plat = sys.platform
		supportedPlatform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
		isatty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
		if not supportedPlatform or not isatty: return False
		return True

	def ReportParentInfo(self, msg):
		spl = map(str.strip, msg.split(':'))
		if self.SupportsColor():
			print('\033[1m\033[93m[+] {}\033[0m: {}'.format(spl[0], spl[1]))
		else:
			print('[+] ' + msg)

	def ReportChildInfo(self, msg):
		spl = map(str.strip, msg.split(':'))
		if self.SupportsColor():
			print('\033[1m\033[93m |  \033[94m{}\033[0m: {}'.format(spl[0], spl[1]))
		else:
			print(' |  ' + msg)

	def ReportParentRisk(self, msg):
		spl = map(str.strip, msg.split(':'))
		if self.SupportsColor():
			print('\033[1m\033[91m[+] {}\033[0m: {}'.format(spl[0], spl[1]))
		else:
			print('[+] ' + msg)

	def ReportChildRisk(self, msg):
		spl = map(str.strip, msg.split(':'))
		if self.SupportsColor():
			print('\033[1m\033[91m |  \033[94m{}\033[0m: {}'.format(spl[0], spl[1]))
		else:
			print(' |  ' + msg)

usage = '%prog [options] destination'
description = 'BackdoorMan is a toolkit that helps you find malicious, hidden and suspicious PHP scripts and shells in a chosen destination.'
version = '%s' % __version__
parser = OptionParser(usage=usage, description=description, version=version)
(opts, args) = parser.parse_args(sys.argv[1:])
if not args: parser.error('no destination supplied')
for dest in args:
	try:
		Man(dest)
	except KeyboardInterrupt:
		print('\nInterrupt: exit')
		sys.exit()
