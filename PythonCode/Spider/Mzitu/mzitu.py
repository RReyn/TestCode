#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib2
import os
from bs4 import BeautifulSoup
import re
import cookielib

headers = {'User-Agent':"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1"}
url = 'http://www.mzitu.com/all'

save_list = []

def urlrequest(url, headers = headers):
	request = urllib2.Request(url, headers = headers)
	reponse = urllib2.urlopen(request)
	html = reponse.read()
	return html
#print html
def getallitems(html, restr):
#	pattern = re.compile('<a href="(.*?)" target="_blank">(.*?)</a>')
	pattern = re.compile(restr, re.S)
	items = re.findall(pattern, html)
#	print items
#	for item in items:
#		print item[0], item[1]
	return items

def additem2list(items):
	for item in items:
		have_li = re.search("</li>", item[0])
		have_a= re.search("</a>", item[0])
		if not have_li and  not have_a:
			save_list.append([item[1].strip(), item[0].strip()])
		#	print item[0], item[1]
def mkdir(path):
	path = path.strip()
	if not os.path.exists(path):
		os.makedirs(path)
		return True

def get_file(url):
	try:
		cj=cookielib.LWPCookieJar()
		opener=urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
		urllib2.install_opener(opener)

		req=urllib2.Request(url)
		operate=opener.open(req)
		data=operate.read()
		return data
	except BaseException, e:
		print e
		return None
def save_file(path, file_name, data):
	if data == None:
		return

	mkdir(path)
	if(not path.endswith("/")):
		path=path+"/"
	file=open(path+file_name, "wb")
	file.write(data)
	file.flush()
	file.close()

def getsuburlitem():
	for item in save_list:
		path = "./Mzitu/" + item[0]
		if not mkdir(path):
			continue
		suburl = item[1]
		for page in range(1, 60):
			page_url = suburl + '/' + str(page)
			img_html = urlrequest(page_url)
			img_url = "".join(getallitems(img_html, '<img src="(.*?)" alt=".*?">'))
			name = img_url[-9:-4]
			name = name + ".jpg"
			data = get_file(img_url)
			save_file(path, name, data)

html = urlrequest(url)
items = getallitems(html, '<a href="(.*?)" target="_blank">(.*?)</a>')
additem2list(items)
getsuburlitem()




