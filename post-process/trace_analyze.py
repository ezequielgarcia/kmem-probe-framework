#!/usr/bin/env python

import sys
import fileinput
import string
import re

class Ptr:
	def __init__(self, fun, ptr, alloc, req):
		self.fun = fun
		self.ptr = ptr
		self.alloc = alloc
		self.req = req

class Callsite:
	def __init__(self, offset):
		self.offset = offset
		self.alloc = 0
		self.req = 0
		self.alloc_count = 0
		self.free_count = 0
		self.ptrs = []

	def curr_alloc(self):
		alloc = 0
		for ptr in self.ptrs:
			alloc += ptr.alloc
		return alloc
			
	def curr_req(self):
		req = 0
		for ptr in self.ptrs:
			req += ptr.req
		return req

f = {}
p = {}

num_allocs = 0
num_frees = 0
num_lost_frees = 0
total_alloc = 0
total_req = 0

def add_kmalloc_event(fun, offset, ptr, req, alloc):

	global num_allocs, total_alloc, total_req
	num_allocs += 1
	total_alloc += alloc
	total_req += req

	ptr_obj = Ptr(fun, ptr, alloc, req)

	if ptr in p:
		print "Duplicate pointer! %s+0x%s, ptr=%s" % (fun, offset, ptr)

	p[ptr] = ptr_obj

	if not fun in f:
		f[fun] = Callsite(offset)

	f[fun].alloc += alloc
	f[fun].req += req
	f[fun].alloc_count += 1
	f[fun].ptrs.append(ptr_obj)

def add_kfree_event(fun, offset, ptr):

	global num_frees, num_lost_frees
	num_frees += 1

	if not ptr in p:
		num_lost_frees += 1
		return

	ptr_obj = p[ptr]
	f[ptr_obj.fun].free_count += 1

	# Remove this ptr from pointers list
	f[ptr_obj.fun].ptrs.remove(ptr_obj)
	# Remove it from pointers dictionary
	del p[ptr] 
	
def main():

	for line in fileinput.input():
		# strip trailing \n, if present
		if line[-1]=='\n':
			line = line[:-1]

		# convert all hex numbers to symbols plus offsets
		# try to preserve column spacing in the output
		tmp = line
		m = re.match(r".*kmalloc.*call_site=([a-zA-Z0-9_]+)\+0x([a-f0-9]+).*ptr=([a-f0-9]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)", tmp)
		if m:
			add_kmalloc_event(m.group(1), 
					  m.group(2),
					  m.group(3),
					  int(m.group(4)),
					  int(m.group(5)))

		m = re.match(r".*kfree.*call_site=([a-zA-Z0-9_+.]+)\+0x([a-f0-9]+).*ptr=([a-f0-9]+)", tmp)
		if m:
			add_kfree_event(m.group(1),
					m.group(2),
					m.group(3))

	curr_alloc = 0
	curr_req = 0
	for fun, callsite in f.items():
		curr_alloc += callsite.curr_alloc()
		curr_req += callsite.curr_req()

	print 'total bytes allocated: %8d' % total_alloc
	print 'total bytes requested: %8d' % total_req
	print 'total bytes wasted:    %8d' % (total_alloc - total_req)
	print 'curr bytes allocated:  %8d' % curr_alloc
	print 'curr bytes requested:  %8d' % curr_req
	print 'curr wasted bytes:     %8d' % (curr_alloc - curr_req)
	print 'number of allocs:      %8d' % num_allocs
	print 'number of frees:       %8d' % num_frees
	print 'number of lost frees:  %8d' % num_lost_frees
	print 'number of callers:     %8d' % len(f)

	print ''
	print '   total      req    waste alloc/free  caller'
	print '---------------------------------------------'
	for fun, callsite in f.items():
		print('%8d %8d %8d %5d/%-5d %s' % (callsite.alloc, 
			 			   callsite.req,
						   callsite.alloc - callsite.req,
						   callsite.alloc_count,
						   callsite.free_count,
						   fun))
	print ''
	print ' current      req    waste    ptrs     caller'
	print '---------------------------------------------'
	for fun, callsite in f.items():
		curr_alloc = callsite.curr_alloc()
		curr_req = callsite.curr_req()
		ptrs_count = len(callsite.ptrs)
		print('%8d %8d %8d %7d     %s' % (curr_alloc, 
						  curr_req,
						  curr_alloc - curr_req,
						  ptrs_count,
						  fun))

if __name__=="__main__":
	main()
