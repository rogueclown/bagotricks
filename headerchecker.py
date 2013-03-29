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

(opts, args) = parser.parse_args()

if not opts.infile:
	print 'input file option (-i) is mandatory.  use -h switch for help.'
	sys.exit(1)

try:
	f = open(opts.infile)
	urls = f.readlines()
	f.close()
except:
	print 'error reading ' + opts.infile
	sys.exit(1)

urls = [url.rstrip() for url in urls]

def extractcookiename(header):
	r =re.compile('\s(.*?)=')
	m = r.search(header)
	cookiename = m.group(0)[1:-1]
	return cookiename

for url in urls:
	print "=" * 60 + '\n'
	print url + '\n'
	try:
		rawheaders = subprocess.check_output(['curl', '--insecure', '-s', '-I', url])
		headers = rawheaders.split('\n')
		if "x-frame-options" not in rawheaders.lower():
			print 'x-frame-options header not present; site may be vulnerable to clickjacking.'
		if "https" in url.lower():
			if 'strict-transport-security' not in rawheaders.lower():
				print 'HSTS header not present.'
		for header in headers:
			if 'set-cookie' in header.lower():
				if 'httponly' not in header.lower():
					print 'HttpOnly option missing from ' + extractcookiename(header) + 'header.'
				if 'https' in url.lower():
					if 'secure' not in header.lower():
						print 'Secure option missing from ' + extractcookiename(header) + 'header.'
	except:
		print "http headers could not be retrieved for " + url
print '=' * 60 + '\n'
