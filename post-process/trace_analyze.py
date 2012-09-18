#!/usr/bin/env python

import sys
import string
import re
import subprocess
from optparse import OptionParser
from os import path, walk
from visualize_mem_tree import visualize_mem_tree

kmalloc_re = r".*kmalloc.*call_site=([a-f0-9]+).*ptr=([a-f0-9]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)"
kfree_re = r".*kfree.*call_site=[a-f0-9+]+.*ptr=([a-f0-9]+)"

cache_alloc_re = r".*cache_alloc.*call_site=([a-f0-9]+).*ptr=([a-f0-9]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)"
cache_free_re = r".*cache_free.*call_site=[a-f0-9+]+.*ptr=([a-f0-9]+)"

both_alloc_re = r".*k.*alloc.*call_site=([a-f0-9]+).*ptr=([a-f0-9]+).*bytes_req=([0-9]+)\s*bytes_alloc=([0-9]+)"
both_free_re = r".*k.*free.*call_site=[a-f0-9+]+.*ptr=([a-f0-9]+)"

class Ptr:
    def __init__(self, fun, ptr, alloc, req):
        self.fun = fun
        self.ptr = ptr
        self.alloc = alloc
        self.req = req


class Callsite:
    def __init__(self):
        self.__alloc = 0
        self.__req = 0
        self.__alloc_count = 0
        self.__free_count = 0
        self.ptrs = []

    def total_alloc(self):
        return self.__alloc

    def alloc_count(self):
        return self.__alloc_count

    def free_count(self):
        return self.__free_count

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

    def curr_waste(self):
        return self.curr_alloc() - self.curr_req()

    def alloc(self, alloc, req, ptr):
        self.__alloc += alloc
        self.__req += req
        self.__alloc_count += 1
        self.ptrs.append(ptr)

    def free(self, ptr):
        self.__free_count += 1
        self.ptrs.remove(ptr)


class EventDB:
    def __init__(self):
        self.f = {}
        self.p = {}
        self.num_allocs = 0
        self.total_alloc = 0
        self.total_req = 0
        self.num_frees = 0
        self.num_lost_frees = 0

    def get_bytes(self):
        alloc = 0
        req = 0
        for fun, callsite in self.f.items():
            alloc += callsite.curr_alloc()
            req += callsite.curr_req()
        return (alloc, req)

    def add_malloc(self, fun, ptr, req, alloc, line):
        self.num_allocs += 1
        self.total_alloc += alloc
        self.total_req += req

        ptr_obj = Ptr(fun, ptr, alloc, req)

        if ptr in self.p:
            print("Duplicate pointer! {}".format(line))

        self.p[ptr] = ptr_obj

        if not fun in self.f:
            self.f[fun] = Callsite()

        self.f[fun].alloc(alloc, req, ptr_obj)

    def add_free(self, ptr):
        self.num_frees += 1

        if not ptr in self.p:
            self.num_lost_frees += 1
            return

        ptr_obj = self.p[ptr]

        self.f[ptr_obj.fun].free(ptr_obj)

        # Remove it from pointers dictionary
        del self.p[ptr]

    def print_stats(self):
        pass

    def print_account(self, filepath, order_by):

        f = open(filepath, 'w')

        curr_alloc = 0
        curr_req = 0
        for fun, callsite in self.f.items():
            curr_alloc += callsite.curr_alloc()
            curr_req += callsite.curr_req()

        f.write("total bytes allocated: %8d\n" % self.total_alloc)
        f.write("total bytes requested: %8d\n" % self.total_req)
        f.write("total bytes wasted:    %8d\n" % (self.total_alloc -
                                              self.total_req))
        f.write("curr bytes allocated:  %8d\n" % curr_alloc)
        f.write("curr bytes requested:  %8d\n" % curr_req)
        f.write("curr wasted bytes:     %8d\n" % (curr_alloc - curr_req))
        f.write("number of allocs:      %8d\n" % self.num_allocs)
        f.write("number of frees:       %8d\n" % self.num_frees)
        f.write("number of lost frees:  %8d\n" % self.num_lost_frees)
        f.write("number of callers:     %8d\n" % len(self.f))
        f.write("\n")
        f.write("   total      slack    net alloc/free  caller\n")
        f.write("---------------------------------------------\n")

        for fun, callsite in sorted(self.f.items(),
                                    key=lambda item: getattr(item[1],
                                                             order_by)(),
                                    reverse=True):

            f.write("%8d %8d %8d %5d/%-5d %s\n" % (callsite.total_alloc(),
                                               callsite.curr_waste(),
                                               callsite.curr_alloc(),
                                               callsite.alloc_count(),
                                               callsite.free_count(),
                                               fun))

        f.close()


class MemTreeNodeSize:
    def __init__(self, node):
        self.__static = 0
        self.__total_dynamic = 0
        self.__curr_dynamic = 0
        self.__waste = 0

        for sym, size in node.data.items():
            self.__static += size
        for sym, call in node.funcs.items():
            self.__total_dynamic += call.total_alloc()
            self.__curr_dynamic += call.curr_alloc()
            self.__waste += call.curr_alloc() - call.curr_req()

    def current(self):
        return self.__static + self.__curr_dynamic

    def waste(self):
        return self.__waste

    def static(self):
        return self.__static

    def current_dynamic(self):
        return self.__curr_dynamic

    def total_dynamic(self):
        return self.__total_dynamic


class MemTreeNode:
    def __init__(self, name="", parent=None, db=None):
        self.name = name
        self.parent = parent
        self.childs = {}
        self.funcs = {}
        self.data = {}
        self.node_size = None

        if db is None:
            if parent is not None:
                self.db = parent.db
        else:
            self.db = db

    def full_name(self):
        l = [self.name,]
        parent = self.parent
        while parent:
            l.append(parent.name)
            parent = parent.parent

        return "/".join(reversed(l))

    def size(self):
        if not self.node_size:
            self.node_size = MemTreeNodeSize(self)
        return self.node_size

    def collapse(self):
        # Collapse one-child empty nodes
        for name, child in self.childs.items():
            if len(child.childs) > 2:
                child.collapse()

            if len(child.childs) == 1 and not child.funcs and not child.data:
                # Remove from child
                (k, v) = child.childs.items()[0]
                del child.childs[k]

                # Add here
                self.childs[k] = v
                v.parent = self

    def strip(self):
        # Remove empty nodes
        for name, child in self.childs.items():
            if child.childs:
                child.strip()
            if not child.funcs and not child.data and not child.childs:
                del self.childs[name]

    def find_first_branch(self, which):
        for name, node in self.childs.items():
            if which == name:
                return node

        for name, node in self.childs.items():
            return node.find_first_branch(which)

        return None

    def treelike(self, level=0):
        str = ""

#       if not self.childs and (static_bytes+dynamic_bytes) == 0:
#           return ""

        if self.name:
            str += "{} - static={} dyn={} tot={}\n".format(self.name,
                                                           self.size().static(),
                                                           self.size().current_dynamic(),
                                                           self.size().total_dynamic())

#       for n, i in self.funcs.items():
#           str += "{}{} - total={} alloc={} req={}\n".format("  "*level, n, i.alloc, i.curr_alloc(), i.curr_req() )

#       for n, i in self.data.items():
#           str += "{}<D>{} - {}\n".format("  "*level, n, i )

        for name, node in self.childs.items():
            child_str = node.treelike(level+1)
            if child_str:
                str += "{}{}"   .format("  "*(level+1), child_str)
        return str

    def fill(self):

        if self.funcs or self.data:
            print "Oooops, already filled"

        filepath = "." + self.full_name() + "/built-in.o"

        output = []
        try:
            p1 = subprocess.Popen(["readelf", "--wide", "-s", filepath], stdout=subprocess.PIPE)
            output = p1.communicate()[0].split("\n")
        except:
            pass

        for line in output:
            if line == '':
                continue
            m = re.match(r".*FUNC.*\b([a-zA-Z0-9_]+)\b", line)
            if m:
                if m.group(1) in self.funcs:
                    print "Duplicate entry! {}".format(m.group(1))

                if m.group(1) in self.db.f:
                    self.funcs[m.group(1)] = self.db.f[m.group(1)]

            m = re.match(r".*([0-9]+)\sOBJECT.*\b([a-zA-Z0-9_]+)\b", line)
            if m:
                self.data[m.group(2)] = int(m.group(1))

    # path is only dir, does not include built-in.o file
    def add_child(self, path):
        # adding a child invalidates node_size object
        self.node_size = None

        parts = path.split('/', 1)
        if len(parts) == 1:
            self.fill()
        else:
            node, others = parts
            if node not in self.childs:
                self.childs[node] = MemTreeNode(node, self)
            self.childs[node].add_child(others)


class SymbolMap:
    def __init__(self, filemap):
        self.fmap = {}
        self.flist = []
        self.cache = {}

        try:
            f = open(filemap)
        except:
            print("Error: Cannot read map file: %s" % filemap)
            sys.exit(1)

        for line in f.readlines():
            (addr_str, symtype, name) = string.split(line, None, 3)
            self.fmap[addr_str] = name
            addr = eval("0x" + addr_str + "L")
            self.flist.append((addr, name))

        f.close()

    def lookup(self, addr_str):

        # return a tuple (string, offset) for a given address
        if addr_str in self.fmap:
            return (self.fmap[addr_str],0)

        # convert address from string to number
        addr = eval("0x" + addr_str + "L")
        if addr in self.cache:
            return self.cache[addr]

        # if address is outside range of addresses in the
        # map file, just return the address without converting it
        if addr < self.flist[0][0] or addr > self.flist[-1][0]:
            return (addr_str,0)

        # no exact match found, now do binary search for closest function
        # do a binary search in funclist for the function
        # use a collapsing range to find the closest addr
        lower = 0
        upper = len(self.flist)-1
        while (lower != upper-1):
            guess_index = lower + (upper-lower)/2
            guess_addr = self.flist[guess_index][0]
            if addr < guess_addr:
                upper = guess_index
            if addr >= guess_addr:
                lower = guess_index

        offset = hex(addr-self.flist[lower][0])
        name = self.flist[lower][1]
        if name.startswith("."):
            name = name[1:]
        self.cache[addr] = (name, offset)
        return (name, offset)


def main():

    parser = OptionParser()
    parser.add_option("-k", "--kernel-path",
                      dest="buildpath",
                      default="linux",
                      help="path to built kernel tree")

    parser.add_option("-a", "--attr",
                      dest="attr",
                      default="current_dynamic",
                      help="attribute to visualize [static, current, \
                                    current_dynamic, total_dynamic, waste]")

    parser.add_option("-f", "--file",
                      dest="file",
                      default="",
                      help="trace log file to analyze")

    parser.add_option("-b", "--start-branch",
                      dest="start_branch",
                      default="linux",
                      help="first directory name to use as ringchart root")

    parser.add_option("-r", "--with-chart",
                      dest="with_chart",
                      action="store_true",
                      help="plot ringchart information")

    parser.add_option("--with-stats",
                      dest="with_stats",
                      action="store_true",
                      help="print statistics")

    parser.add_option("--malloc",
                      dest="do_malloc",
                      action="store_true",
                      help="trace kmalloc/kfree only")

    parser.add_option("--cache",
                      dest="do_cache",
                      action="store_true",
                      help="trace kmem_cache_alloc/kmem_cache_free only")

    parser.add_option("--account-file",
                      dest="account_file",
                      default="",
                      help="show output matching slab_account output")

    (opts, args) = parser.parse_args()

    if len(opts.file) == 0:
        print "I need a trace log file!"
        return

    if opts.with_chart is None:
        opts.with_chart = False

    if opts.with_stats is None:
        opts.with_stats = False

    if opts.do_malloc is True and opts.do_cache is None:
        print "Filtering kmalloc events only ..."
        alloc_re = kmalloc_re
        free_re = kfree_re

    elif opts.do_malloc is None and opts.do_cache is True:
        print "Filtering kmem_cache events only ..."
        alloc_re = cache_alloc_re
        free_re = cache_free_re

    else:
        print "Filtering all ..."
        alloc_re = both_alloc_re
        free_re = both_free_re

    print "Reading symbol map at {}...".format(opts.buildpath)
    symbol = SymbolMap(opts.buildpath + "/System.map")

    rootDB = EventDB()

    print "Slurping event log ..."
    logfile = open(opts.file)
    for line in logfile:

        m = re.match(alloc_re, line)
        if m:
            (fun, offset) = symbol.lookup(m.group(1))
            rootDB.add_malloc(fun, #"{}+{}".format(fun,offset),
                              m.group(2),
                              int(m.group(3)),
                              int(m.group(4)), line)

        m = re.match(free_re, line)
        if m:
            rootDB.add_free(m.group(1))

    print "Creating tree from compiled symbols at {} ...".format(opts.buildpath)
    tree = MemTreeNode("", db=rootDB)
    for root, dirs, files in walk(opts.buildpath):
        for filepath in [path.join(root,f) for f in files]:
            if filepath.endswith("built-in.o"):
                tree.add_child(filepath)

    print "Cleaning tree ..."
    tree.collapse()
    tree.strip()

    print(tree.find_first_branch(opts.start_branch).treelike())

    if len(opts.account_file) != 0:
        rootDB.print_account(opts.account_file, "curr_waste")

    if opts.with_stats:
        rootDB.print_stats()

    if opts.with_chart:
        visualize_mem_tree(tree.find_first_branch(opts.start_branch),
                           attr=opts.attr,
                           filename=opts.start_branch)

if __name__ == "__main__":
    main()
