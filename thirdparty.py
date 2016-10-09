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

import requests, json
from time import sleep

with open('config.json', 'r') as f:
	config = json.load(f)

def VirusTotal(file):
	apikey = config['VirusTotal_apikey']
	if apikey == '':
		return False
	try:
		r = requests.post('https://virustotal.com/vtapi/v2/file/scan', data={'apikey': apikey}, files={'file': file})
		data = r.json()
		if data['response_code'] == 0:
			return False
		sleep(3)
		r = requests.post("https://www.virustotal.com/vtapi/v2/file/report", data={"apikey": apikey, "resource": data["resource"]})
		try:
			data = r.json()
		except:
			return False
		if data['response_code'] == 0 or data['positives'] == 0:
			return False
		return data
	except requests.ConnectionError:
		return False

def ShellRay(file):
	try:
		r = requests.post('https://shellray.com/upload', files={'file': file})
		data = r.json()
		if not data['infected']:
			return False
		return data
	except requests.ConnectionError:
		return False
