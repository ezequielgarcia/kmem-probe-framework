#!/usr/bin/env python

import sys
import string
import re
import subprocess
from optparse import OptionParser
from os import path, walk

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

    def total_dynamic(self):
        return self.__alloc

    def alloc_count(self):
        return self.__alloc_count

    def free_count(self):
        return self.__free_count

    def current_dynamic(self):
        alloc = 0
        for ptr in self.ptrs:
            alloc += ptr.alloc
        return alloc

    def current_req(self):
        req = 0
        for ptr in self.ptrs:
            req += ptr.req
        return req

    def waste(self):
        return self.current_dynamic() - self.current_req()

    def do_alloc(self, alloc, req, ptr):
        self.__alloc += alloc
        self.__req += req
        self.__alloc_count += 1
        self.ptrs.append(ptr)

    def do_free(self, ptr):
        self.__free_count += 1
        self.ptrs.remove(ptr)


class EventDB:
    def __init__(self):
        self.f = {}
        self.p = {}
        self.num_allocs = 0
        self.total_dynamic = 0
        self.total_req = 0
        self.num_frees = 0
        self.num_lost_frees = 0

    def get_bytes(self):
        alloc = 0
        req = 0
        for fun, callsite in self.f.items():
            alloc += callsite.current_dynamic()
            req += callsite.current_req()
        return (alloc, req)

    def add_malloc(self, fun, ptr, req, alloc, line):
        self.num_allocs += 1
        self.total_dynamic += alloc
        self.total_req += req

        ptr_obj = Ptr(fun, ptr, alloc, req)

        if ptr in self.p:
            print("[WARNING] Duplicate pointer! {}".format(line))

        self.p[ptr] = ptr_obj

        if not fun in self.f:
            self.f[fun] = Callsite()

        self.f[fun].do_alloc(alloc, req, ptr_obj)

    def add_free(self, ptr):
        self.num_frees += 1

        if not ptr in self.p:
            self.num_lost_frees += 1
            return

        ptr_obj = self.p[ptr]

        self.f[ptr_obj.fun].do_free(ptr_obj)

        # Remove it from pointers dictionary
        del self.p[ptr]

    def print_account(self, filepath, order_by, filter_tree=None):

        current_dynamic = 0
        current_req = 0
        alloc_count = 0
        free_count = 0

        if filter_tree is None:
            filter_symbol = lambda f: True
        else:
            filter_symbol = filter_tree.symbol_is_here

        syms = [(f,c) for f,c in self.f.items() if filter_symbol(f)]

        f = open(filepath, 'w')

        for fun, callsite in syms:
            current_dynamic += callsite.current_dynamic()
            current_req += callsite.current_req()
            alloc_count += callsite.alloc_count()
            free_count += callsite.free_count()

        f.write("current bytes allocated: {:>10}\n".format(current_dynamic))
        f.write("current bytes requested: {:>10}\n".format(current_req))
        f.write("current wasted bytes:    {:>10}\n".format((current_dynamic -
                                                         current_req)))
        f.write("number of allocs:        {:>10}\n".format(alloc_count))
        f.write("number of frees:         {:>10}\n".format(free_count))
        f.write("number of callers:       {:>10}\n".format(len(syms)))
        f.write("\n")
        f.write("   total    waste      net alloc/free  caller\n")
        f.write("---------------------------------------------\n")

        for fun, callsite in sorted(syms,
                                    key=lambda item: getattr(item[1],
                                                             order_by)(),
                                    reverse=True):

            f.write("%8d %8d %8d %5d/%-5d %s\n" % (callsite.total_dynamic(),
                                               callsite.waste(),
                                               callsite.current_dynamic(),
                                               callsite.alloc_count(),
                                               callsite.free_count(),
                                               fun))

        f.close()


class MemTreeNodeSize:
    def __init__(self, node):
        self.__static = 0
        self.__total_dynamic = 0
        self.__current_dynamic = 0
        self.__waste = 0

        # First for my symbols
        for sym, size in node.data.items():
            self.__static += size
        for sym, size in node.text.items():
            self.__static += size
        for sym, call in node.funcs.items():
            self.__total_dynamic += call.total_dynamic()
            self.__current_dynamic += call.current_dynamic()
            self.__waste += call.current_dynamic() - call.current_req()

        # Now, for my children's symbols.
        # Or, instead, we could first add all my children's
        # symbols here and then get the node size.
        for name, child in node.childs.items():
            self.__total_dynamic += child.size().total_dynamic()
            self.__current_dynamic += child.size().current_dynamic()
            self.__static += child.size().static()
            self.__waste += child.size().waste()

    def current(self):
        return self.__static + self.__current_dynamic

    def waste(self):
        return self.__waste

    def static(self):
        return self.__static

    def current_dynamic(self):
        return self.__current_dynamic

    def total_dynamic(self):
        return self.__total_dynamic


class MemTreeNode:
    def __init__(self, name="", parent=None, db=None):
        self.name = name
        self.parent = parent
        self.childs = {}
        self.funcs = {}
        self.data = {}
        self.text = {}
        self.node_size = None
        self.fill = getattr(self, "fill_per_file")

        if db is None:
            if parent is not None:
                self.db = parent.db
        else:
            self.db = db

    def symbol_is_here(self, symbol):
        if symbol in self.funcs:
            return True
        else:
            for name, child in self.childs.items():
                if child.symbol_is_here(symbol):
                    return True
        return False

    def full_name(self):
        l = [self.name,]
        parent = self.parent
        while parent:
            if parent.name != "":
                l.append(parent.name)
            parent = parent.parent

        return "/".join(reversed(l))

    def size(self):
        if self.node_size is None:
            self.node_size = MemTreeNodeSize(self)
        return self.node_size

    def __collapse(self):
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

    def __strip(self):
        # Remove empty nodes
        for name, child in self.childs.items():
            if child.childs:
                child.__strip()
            if not child.funcs and not child.data and not child.childs:
                del self.childs[name]

    def __get_root(self):
        if len(self.name) == 0:
            if len(self.childs) == 1:
                child = self.childs.itervalues().next()
                return child.__get_root()

        return self

    def get_clean(self):
        self.__collapse()
        self.__strip()
        return self.__get_root()

    def find_first_branch(self, which):
        for name, node in self.childs.items():
            if which == name:
                return node

        for name, node in self.childs.items():
            return node.find_first_branch(which)

        print("[WARNING] Can't find first branch '{}'".format(which))
        return None

    def treelike(self, level=0, attr="current_dynamic"):
        str = ""
        str += "{}\n".format(self.name)
        for name, node in self.childs.items():
            child_str = node.treelike(level+1, attr)
            if child_str:
                str += "{}{}".format("  "*(level+1), child_str)
        return str

    def treelike2(self, level=0, attr="current_dynamic"):
        str = ""

        attr_val = getattr(self.size(), attr)()

        if self.name and attr_val != 0:
            str += "{} - {}={}\n".format(self.name, attr, attr_val)

        for name, node in self.childs.items():
            child_str = node.treelike(level+1, attr)
            if child_str:
                str += "{}{}".format("  "*(level+1), child_str)
        return str

    def fill_per_file(self, path):

        filepath = "{}/{}".format(self.full_name(), path)

        if path not in self.childs:
            self.childs[path] = MemTreeNode(path, self)

        child = self.childs[path]

        output = []
        try:
            p1 = subprocess.Popen(["readelf", "--wide", "-s", filepath], stdout=subprocess.PIPE)
            output = p1.communicate()[0].split("\n")
        except:
            pass

        for line in output:
            if line == '':
                continue

            m = re.match(r".*\s([0-9]+)\sFUNC.*\s+([a-zA-Z0-9_\.]+)\b", line)
            if m:
                if m.group(2) in child.text:
                    print "Duplicate text entry! {}".format(m.group(2))
                child.text[m.group(2)] = int(m.group(1))

                if m.group(2) in child.db.f:
                    child.funcs[m.group(2)] = child.db.f[m.group(2)]

            m = re.match(r".*\s([0-9]+)\sOBJECT.*\s+([a-zA-Z0-9_\.]+)\b", line)
            if m:
                if m.group(2) in child.data:
                    print "[WARNING] Duplicate data entry! {}".format(m.group(2))
                child.data[m.group(2)] = int(m.group(1))

    def fill_per_dir(self, path):

        if self.funcs or self.data:
            print "[WARNING] Oooops, already filled"

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
                    print "[WARNING] Duplicate entry! {}".format(m.group(1))

                if m.group(1) in self.db.f:
                    self.funcs[m.group(1)] = self.db.f[m.group(1)]

            m = re.match(r".*([0-9]+)\sOBJECT.*\b([a-zA-Z0-9_]+)\b", line)
            if m:
                self.data[m.group(2)] = int(m.group(1))

    # path is should be an object file, like fs/ext2/inode.o
    def add_child(self, path):
        # adding a child invalidates node_size object
        self.node_size = None

        parts = path.split('/', 1)
        if len(parts) == 1:
            self.fill(path)
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
            print("[ERROR] Cannot read map file: %s" % filemap)
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
    parser.add_option("-k", "--kernel",
                      dest="buildpath",
                      default="",
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
                      default="",
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

    # Kernel build path is a mandatory parameter.
    # We need to look at compiled objects and also for System.map.
    if opts.buildpath == "":
        print "Please set a kernel build path!"
        parser.print_help()
        return

    # Clean user provided kernel path from dirty slashes
    opts.buildpath = opts.buildpath.rstrip("/")

    # If we don't have a trace log file,
    # then we'll fallback to static report mode.
    if len(opts.file) == 0:
        print "No trace log file specified: will report on static size only"
        opts.attr = "static"
        opts.do_malloc = False
        opts.do_cache = False
        opts.account_file = ""
        opts.with_chart = True
        opts.with_stats = False
        opts.just_static = True
    else:
        opts.just_static = False

    if opts.with_chart is None:
        opts.with_chart = False

    if opts.with_stats is None:
        opts.with_stats = False

    if opts.do_malloc is True and opts.do_cache is None:
        print "Filtering kmalloc events only"
        alloc_re = kmalloc_re
        free_re = kfree_re

    elif opts.do_malloc is None and opts.do_cache is True:
        print "Filtering kmem_cache events only"
        alloc_re = cache_alloc_re
        free_re = cache_free_re

    else:
        if not opts.just_static:
            print "Filtering all"
            alloc_re = both_alloc_re
            free_re = both_free_re

    print "Reading symbol map at {}".format(opts.buildpath)
    symbol = SymbolMap(opts.buildpath + "/System.map")

    rootDB = EventDB()

    if not opts.just_static:
        print "Slurping event log"
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

    root_path = "{}/{}".format(opts.buildpath, opts.start_branch).rstrip("/")

    blacklist = ("scripts", "tools")

    print "Creating tree from compiled symbols at {}".format(root_path)
    tree = MemTreeNode(db = rootDB)
    for root, dirs, files in walk(root_path):

        do_blacklist = False
        for bdir in blacklist:
            if root.startswith("{}/{}".format(root_path, bdir)):
                do_blacklist = True

        if do_blacklist:
            continue

        for filepath in [path.join(root,f) for f in files]:
            if filepath.endswith(".o") and \
                filepath.endswith("built-in.o") == False and \
                filepath.endswith("vmlinux.o") == False:
                tree.add_child(filepath)
#            if filepath.endswith("built-in.o") and \
#                filepath.endswith("vmlinux.o") == False:
#                tree.add_child(filepath)

    print "Cleaning tree"
    tree = tree.get_clean()

    print(tree.treelike(attr = opts.attr))

    if len(opts.account_file) != 0:
        print "Creating account file at {}".format(opts.account_file)
        rootDB.print_account(opts.account_file,
                             opts.attr,
                             tree)

    if opts.with_stats:
        rootDB.print_stats()

    if opts.with_chart:
        filename = "linux"
        if len(opts.start_branch) != 0:
            filename = opts.start_branch
            tree = tree.find_first_branch(opts.start_branch)

        print "Creating ringchart file at {}.png".format(filename)
        from visualize_mem_tree import visualize_mem_tree
        visualize_mem_tree(tree, opts.attr, filename)

if __name__ == "__main__":
    main()
