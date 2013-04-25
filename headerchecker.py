#!/usr/bin/python

# headerchecker.py
#
# checks http headers for common flaws such as lack of framebusting controls, 
# lack of secure and httponly cookie flags, and lack of HSTS implementation.
#
# rogueclown, march 2013
# licensed under the WTFPL, http://www.wtfpl.net/txt/copying.

import subprocess
import re
from optparse import OptionParser
from sys import exit

parser = OptionParser(usage='usage: %prog -i url_list')
parser.add_option('-i', '--inputfile', dest='infile', help='list of URLs.  one per line.  needs http or https prefix.')
parser.add_option('-s', '--sorting', dest='sort', help='sort format.  choose "host" for sorting by host, or "vuln" for sorting by vulnerability.  defaults to sorting by vulnerability.')

(opts, args) = parser.parse_args()

if not opts.infile:
	print 'input file option (-i) is mandatory.  use -h switch for help.'
	exit(1)

try:
	f = open(opts.infile)
	urls = f.readlines()
	f.close()
except:
	print 'error reading ' + opts.infile
	exit(1)

if opts.sort == 'host':
	sort = 'host'
else:
	sort = 'vuln'

if sort == 'vuln':
	clickjack = []
	hstsabsent = []
	nosecure = []
	nohttponly = []
	noheaders = []
	csp = []

urls = [url.rstrip() for url in urls]

def extractcookiename(header):
	r =re.compile('\s(.*?)=')
	m = r.search(header)
	cookiename = m.group(0)[1:-1]
	return cookiename

for url in urls:
	if sort != 'vuln':
		print "=" * 60 + '\n'
		print url + '\n'
	try:
		rawheaders = subprocess.check_output(['curl', '--insecure', '--max-time', '5', '--connect-timeout', '0', '-s', '-I', url])
		headers = rawheaders.split('\n')
		if "x-content-security-policy" not in rawheaders.lower():
			if sort == 'vuln':
				csp.append(url)
			else
				print 'x-content-security-policy header not present.'
		if "x-frame-options" not in rawheaders.lower():
			if sort == 'vuln':
				clickjack.append(url)
			else:
				print 'x-frame-options header not present; site may be vulnerable to clickjacking.'
		if "https" in url.lower():
			if 'strict-transport-security' not in rawheaders.lower():
				if sort == 'vuln':
					hstsabsent.append(url)
				else:
					print 'HSTS header not present.'
		for header in headers:
			if 'set-cookie' in header.lower():
				if 'httponly' not in header.lower():
					if sort == 'vuln':
						nohttponly.append(url + ' (cookie: ' + extractcookiename(header) + ')')
					else:
						print 'HttpOnly option missing from ' + extractcookiename(header) + ' cookie.'
				if 'https' in url.lower():
					if 'secure' not in header.lower():
						if sort == 'vuln':
							nosecure.append(url + ' (cookie: ' + extractcookiename(header) + ')')
						else:
							print 'Secure option missing from ' + extractcookiename(header) + ' cookie.'
	except:
		if sort == 'vuln':
			noheaders.append(url)
		else:		
			print "http headers could not be retrieved for " + url
print '=' * 60 + '\n'

# print output if sorted by vuln
if sort == 'vuln':
	print 'x-frame-options header not present; site may be vulnerable to clickjacking:\n'
	for url in clickjack:
		print url
	print '=' * 60
	print '\n'
	print 'HSTS header not present:\n'
	for url in hstsabsent:
		print url
	print '=' * 60
	print '\n'
	print 'content security policy header not present.\n'
	for url in csp:
		print url
	print '=' * 60
	print '\n'
	print 'HttpOnly option missing:\n'
	for url in nohttponly:
		print url
	print '=' * 60
	print '\n'
	print 'Secure option missing:\n'
	for url in nosecure:
		print url
