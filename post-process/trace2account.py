#!/usr/bin/env python

import sys
import fileinput
import string
import re

# map function call_site to total site allocated bytes
callmap = {}

num_allocs = 0
num_frees = 0
num_callers = 0
total_alloc = 0
total_req = 0
total_slack = 0

def init_call(call):
	global num_callers
	num_callers += 1
	callmap[call] = {}
	callmap[call]['total'] = 0
	callmap[call]['req'] = 0
	callmap[call]['slack'] = 0
	callmap[call]['alloc'] = 0
	callmap[call]['free'] = 0


def add_kmalloc_event(call, req, real):
	if not callmap.has_key(call):
		init_call(call)

	global num_allocs, total_alloc, total_req, total_slack
	num_allocs += 1
	total_alloc += real
	total_req += req
	total_slack += (real - req)

	callmap[call]['total'] += real
	callmap[call]['req'] += req
	callmap[call]['slack'] += (real - req)
	callmap[call]['alloc'] += 1

def add_kfree_event(call):
	if not callmap.has_key(call):
		init_call(call)

	global num_frees
	num_frees += 1
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

	print 'total bytes allocated: %8d' % total_alloc
	print 'total bytes requested: %8d' % total_req
	print 'slack bytes allocated: %8d' % total_slack
	print 'number of allocs:      %8d' % num_allocs
	print 'number of frees:       %8d' % num_frees
	print 'number of callers:     %8d' % num_callers
	print ''
	print '   total    slack      req alloc/free  caller'

	for call in callmap.keys():
		print('%8d %8d %8d %5d/%-5d %s' % (callmap[call]['total'], 
			 			   callmap[call]['slack'],
						   callmap[call]['req'],
						   callmap[call]['alloc'],
						   callmap[call]['free'],
						   call))

if __name__=="__main__":
	main()
