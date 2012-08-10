#!/usr/bin/env python

# addr2sym.py - resolve addresses to symbols, using a map file
# Reads a log file, and map file, and substitutes function
# names and offsets for numeric values in the log.
# The re-written log file is sent to standard out.
#
# A normal usage looks like:
# cat boot.log | addr2sym -m linux-2.6.7/System.map >boot.lst
#
import sys
import fileinput
import string
import re

def startswith(str, pattern):
	if string.find(str, pattern)==0:
		return 1
	else:
		return 0

def print_error(str):
	sys.stderr.write(str+"\n");
	sys.stderr.flush()

# returns function map (key=addr, value=funcname) and
# a list of function tuples (addr, funcname)
def read_map(filename):
	global map_low, map_high
	funcmap = {}
	funclist = []
	try:
		f = open(filename)
	except:
		print_error("Error: Cannot read map file: %s" % filename)
		usage()

	for line in f.readlines():
		#print("debug " + line)
		(addr_str, symtype, funcname) = string.split(line, None, 3)
		#print(addr_str + "," + symtype + "," + funcname)
		funcmap[addr_str] = funcname
		addr = eval("0x" + addr_str + "L")
		funclist.append((addr, funcname))

	return (funcmap, funclist)

callsite_cache = {}

# return string with function and offset for a given address
def lookup_sym(funcmap, funclist, addr_str):
	global callsite_cache

	try:
		return funcmap[addr_str]
	except:
		pass

	# no exact match found, now do binary search for closest function

	# convert address from string to number
	addr = eval(addr_str)

	# if address is outside range of addresses in the
	# map file, just return the address without converting it
	if addr < funclist[0][0] or addr > funclist[-1][0]:
		return addr_str

	if callsite_cache.has_key(addr):
		return callsite_cache[addr]

	# do a binary search in funclist for the function
	# use a collapsing range to find the closest addr
	lower = 0
	upper = len(funclist)-1
	while (lower != upper-1):
		guess_index = lower + (upper-lower)/2
		guess_addr = funclist[guess_index][0]
		if addr < guess_addr:
			upper = guess_index
		if addr >= guess_addr:
			lower = guess_index
	
	offset = addr-funclist[lower][0]
	name = funclist[lower][1]
	if startswith(name, "."):
		name = name[1:]
	func_str = "%s+0x%x" % (name, offset)
	callsite_cache[addr] = func_str
	return func_str

def usage():
	print "Usage: addr2sym <infile -m mapfile >outfile"
	print "\nexample:"
	print "addr2sym <boot.log -m linux-2.6.7/System.map >boot.lst"
	sys.exit(1)

def main():
	# user must have "-m mapfile" at a minimum
	# TODO: You can also try to read /proc/kallsym (perhaps with in-situ option)
	if len(sys.argv)<3:
		print_error("Error: no map file specified")
		usage()
	
	mapfilename = ""
	i = 0
	while i < len(sys.argv):
		if sys.argv[i]=="-m":
			try:
				mapfilename = sys.argv[i+1]
				# remove the args from the argument list
				sys.argv[i:i+2]=[]
			except:
				pass
		i = i+1

	if not mapfilename:
		print_error("Error: missing map file name")
		usage()

	# read function names and addresses from map file
	(funcmap, funclist) = read_map(mapfilename)

	for line in fileinput.input():
		# strip trailing \n, if present
		if line[-1]=='\n':
			line = line[:-1]

		# convert all hex numbers to symbols plus offsets
		# try to preserve column spacing in the output
		tmp = line
		new_line = ""
		m = re.match(r".*?call_site=([0-9abcdef]+)(\s*)", tmp)

		if m:
			# addr is match for re group 1, look it up
			addr_str = "0x" + tmp[m.start(1): m.end(1)]

			func = lookup_sym(funcmap, funclist, addr_str)

			# replace call_site address with call_site symbol name
			new_line = new_line + tmp[:m.start(1)] + func + tmp[m.end(1):]
			end = m.end(1)

			# pad line to keep columns the same
			# whitespace might match or not.  If it does, it's
			# group 2 from the regex above.
			if len(m.groups())>1: # if we also matched whitespace
				end = m.end(2)
				pad_count = (m.end(2)-m.start(1))-len(func)
				if pad_count < 1: pad_count=1
				new_line = new_line + " "*pad_count

		if new_line:
			line = new_line
		print line
	
if __name__=="__main__":
	main()
