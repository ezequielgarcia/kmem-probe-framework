#!/usr/bin/env python

import sys
import fileinput
import string
import re

# map function call_site to total site allocated bytes
callmap = {}

def init_call(call):
	callmap[call] = {}
	callmap[call]['total'] = 0
	callmap[call]['req'] = 0
	callmap[call]['slack'] = 0
	callmap[call]['alloc'] = 0
	callmap[call]['free'] = 0


def add_kmalloc_event(call, req, real):
	if not callmap.has_key(call):
		init_call(call)

	callmap[call]['total'] += real
	callmap[call]['req'] += req
	callmap[call]['slack'] += (real - req)
	callmap[call]['alloc'] += 1

def add_kfree_event(call):
	if not callmap.has_key(call):
		init_call(call)

	callmap[call]['free'] += 1

def main():

	for line in fileinput.input():
		# strip trailing \n, if present
		if line[-1]=='\n':
			line = line[:-1]

		# convert all hex numbers to symbols plus offsets
		# try to preserve column spacing in the output
		tmp = line
		m = re.match(r".*kmalloc.*call_site=([a-zA-Z0-9_+.]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)", tmp)
		if m:
			add_kmalloc_event(m.group(1), int(m.group(2)), int(m.group(3)))

		m = re.match(r".*kfree.*call_site=([a-zA-Z0-9_+.]+)", tmp)

		if m:
			add_kfree_event(m.group(1))

	print 'total (req)\tslack\tcaller\t\talloc/free'
	for call in callmap.keys():
		print '{0} ({1})\t{2}\t{3}\t{4}/{5}'.format(callmap[call]['total'],
							callmap[call]['req'],
							callmap[call]['slack'],
							call,
							callmap[call]['alloc'],
							callmap[call]['free'])
	
if __name__=="__main__":
	main()
