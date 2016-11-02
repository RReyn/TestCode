#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import urllib2
import re
import thread
import time

class QSBK:
	def __init__(self):
		self.pageIndex = 1
		self.user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
		self.headers = {'User-Agent': self.user_agent}
		self.stories = []
		self.enable = False

	def getPage(self, pageIndex):
		try:
			url = "http://www.qiushibaike.com/hot/page" + str(pageIndex)
			request = urllib2.Request(url, headers = self.headers)
			reponse = urllib2.urlopen(request)
			pageCode = reponse.read().decode('utf-8')
	#		print pageCode

			return pageCode
		except urllib2.URLError, e:
			if hasattr(e, 'reason'):
				print u'connect qiushibaike failed,errror:',e.reason
				return None

	def getPageItems(self, pageIndex):
		pageCode = self.getPage(pageIndex)

		if not pageCode:
			print 'failed to load pages...'
			return None

#		pattern = re.compile('<div.*?author clearfix">.*?h2>(.*?)</h2.*?<a.*?<img.*?>.*?<div.*?'+
#				'content">.*?<span>(.*?)</span>.*?</div>(.*?)<div class="stats.*?class="number">(.*?)</i>', re.S)
		pattern = re.compile('<div.*?author clearfix">.*?h2>(.*?)</h2.*?<a.*?<img.*?>.*?<div.*?'+
				'content">.*?<span>(.*?)</span>.*?<div class="stats.*?class="number">(.*?)</i>', re.S)
		items = re.findall(pattern, pageCode)
		pageStories = []

		for item in items:
#			haveImg = re.search("img", item[3])
			haveImg = re.search("img", item[1])
			if not haveImg:
				replaceBR = re.compile('<br/>')
				text = re.sub(replaceBR, "\n", item[1])
				# item[0]:Author, item[1]:content, item[2]:Like
			#	pageStories.append([item[0].strip(), text.strip(),item[2].strip(),item[3].strip()])
				pageStories.append([item[0].strip(), text.strip(),item[1].strip(),item[2].strip()])
		return pageStories

	def loadPage(self):
		if self.enable == True:
			if len(self.stories) < 2:
				pageStories = self.getPageItems(self.pageIndex)
				if pageStories:
					self.stories.append(pageStories)
					self.pageIndex += 1


	def getOneStory(self, pageStories, page):
		for story in pageStories:
			input = raw_input()
			self.loadPage()
			if input == "Q":
				self.enable = False
				return
			print u'Page %d\tAuthor:%s\tLike:%s\n%s'%(page,story[0],story[3],story[1])

	def start(self):
		print u"Reading QiuShiBaiKe, enter 'Enter' to read new story, enter 'Q' to Quit"
		self.enable = True
		self.loadPage()
		nowPage = 0
		while self.enable:
			if len(self.stories) > 0:
				pageStories = self.stories[0]
				nowPage += 1
				del self.stories[0]
				self.getOneStory(pageStories,nowPage)


spider = QSBK()
spider.start()
