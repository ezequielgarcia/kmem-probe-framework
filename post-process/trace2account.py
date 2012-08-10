#!/usr/bin/env python

import sys
import fileinput
import string
import re

def main():
	# map function call_site to total site allocated bytes
	callmap = {}

	for line in fileinput.input():
		# strip trailing \n, if present
		if line[-1]=='\n':
			line = line[:-1]

		# convert all hex numbers to symbols plus offsets
		# try to preserve column spacing in the output
		tmp = line
		m = re.match(r".*kmalloc.*call_site=([a-zA-Z0-9_+.]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)", tmp)

		if m:
			call = m.group(1)
			req = int(m.group(2))
			alloc = int(m.group(3))

			if not callmap.has_key(call):
				callmap[call] = {}
				callmap[call]['alloc'] = 0
				callmap[call]['req'] = 0
				callmap[call]['slack'] = 0

			callmap[call]['alloc'] += alloc
			callmap[call]['req'] += req
			callmap[call]['slack'] += (alloc - req)

	print 'total\treq\tslack\tcaller'
	for call in callmap.keys():
		print '{0}\t{1}\t{2}\t{3}'.format(callmap[call]['alloc'], callmap[call]['req'], callmap[call]['slack'], call)
	
if __name__=="__main__":
	main()
