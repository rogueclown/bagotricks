#!/usr/bin/python

# peepcompile.py
#
# takes lists of hostnames and IP addresses with web ports open, and compiles
# them into a list of addresses that can be fed to Tim Tomes' PeepingTom script
# (https://bitbucket.org/LaNMaSteR53/peepingtom)
#
# rogueclown, april 2013
# licensed under the WTFPL, http://www.wtfpl.net/txt/copying.

import subprocess
import re
from optparse import OptionParser
from sys import exit

parser = OptionParser(usage='usage: %prog -h http_addresses -s https_addresses -b addresses_http_and_https -n nmap_text_output -o output_file')
parser.add_option('-p', '--http', dest='httpaddresses', help='list of IP addresses and domains at which to take screenshots of the http page.')
parser.add_option('-s', '--https', dest='httpsaddresses', help='list of IP addresses and domains at which to take screenshots of the https page.')
parser.add_option('-b', '--both', dest='bothaddresses', help='list of IP addresses and domains for which to screenshot both http and https pages.')
parser.add_option('-n', '--nmap', dest='nmapoutput', help='nmap output in text format "host port proto service state".')
parser.add_option('-o', '--outfile', dest='outfile', help='file name for output list of addresses.')

(opts, args) = parser.parse_args()

if not opts.outfile:
	print 'error: output file name required.  use -h switch for help.'
	exit(1)

try:
	outfile = open(opts.outfile, 'a')
except:
	print 'error opening ' + opts.outfile + ' for writing.'
	exit(1)

# initiate list of lines to write to output file
# not writing to file until end, since we want to avoid duplication.
lines_to_write = []

if opts.httpaddresses:
	try:
		f = open(opts.httpaddresses, 'r')
		httpaddresses = f.readlines()
		f.close()
	except:
		print 'error opening ' + opts.httpaddresses + ' for reading.'
		exit(1)

	for address in httpaddresses:
		lines_to_write.append('http://' + address)

if opts.httpsaddresses:
	try:
		f = open(opts.httpsaddresses, 'r')
		httpsaddresses = f.readlines()
		f.close()
	except:
		print 'error opening ' + opts.httpsaddresses + ' for reading.'
		exit(1)

	for address in httpsaddresses:
		lines_to_write.append('https://' + address)

if opts.bothaddresses:
        try:
                f = open(opts.bothaddresses, 'r')
                bothaddresses = f.readlines()
                f.close()
        except:
                print 'error opening ' + opts.bothaddresses + ' for reading.'
                exit(1)

        for address in bothaddresses:
		lines_to_write.append('http://' + address)
                lines_to_write.append('https://' + address)

if opts.nmapoutput:
	try:
		f = open(opts.nmapoutput, 'r')
		nmapoutput = f.readlines()
		f.close()
	except:
		print 'error opening ' + opts.nmapoutput + ' for reading.'
		exit(1)

	for line in nmapoutput:
		# split line into [IP, port, proto, service, state] list
		fields = line.split()
		if len(fields) != 5:
			# control for blank lines
			pass
		elif "https" in fields[3]:
			if fields[1] == '443':
				lines_to_write.append('https://' + fields[0] + '\n')
			else:
				lines_to_write.append('https://' + fields[0] + ':' + fields[1] + '\n')
		elif "http" in fields[3]:
			if fields[1] == '80':
				lines_to_write.append('http://' + fields[0] + '\n')
			else:
				lines_to_write.append('http://' + fields[0] + ':' + fields[1] + '\n')

# check for duplicate addresses, and write to output file
lines_seen = set()
for line in lines_to_write:
	if line not in lines_seen:
		outfile.write(line)
		lines_seen.add(line)

# close output file 
outfile.close()
