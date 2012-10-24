#!/usr/bin/env python
#
# Copyright (C) 2012 Ezequiel Garcia <elezegarcia@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#
# TODO: Add a lot more comments and add docstrings!

import sys
import string
import re
import subprocess
import math
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

    def print_callers(self, filepath, filter_tree=None):

        if filter_tree is None:
            filter_symbol = lambda f: True
        else:
            filter_symbol = filter_tree.symbol_is_here

        syms = [(f,c) for f,c in self.f.items() if filter_symbol(f)]

        f = open(filepath, 'w')

        for name, c in syms:

            symdir = filter_tree.get_symbol_dir(name)
            f.write("{:<60} {:<8} {:<8} {:<8}\n".format(name,
                                           c.current_dynamic(),
                                           c.waste(),
                                           symdir))

        f.close()

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

    def get_symbol_dir(self, symbol):
        if symbol in self.funcs:
            return self.full_name()
        else:
            for name, child in self.childs.items():
                symdir = child.get_symbol_dir(symbol)
                if symdir is not None:
                    return symdir
        return None

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
                child.__collapse()

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
        if len(self.childs) == 1:
            child = self.childs.itervalues().next()
            # This is a pedantic test, the first node with
            # multiple childs is the root we're searching
            if not child.name.endswith(".o"):
                return child.__get_root()

        return self

    # Obtain a clean tree.
    # We do it this way because collapse() and strip() must be called
    # in an ordered fashion.
    def get_clean(self):
        self.__collapse()
        self.__strip()
        return self.__get_root()

    def find_first_branch(self, which):
        if self.name == which:
            return self

        for name, node in self.childs.items():
            if which == name:
                return node

        for name, node in self.childs.items():
            return node.find_first_branch(which)

        print("[WARNING] Can't find first branch '{}'".format(which))
        return None

    # This are for debug purposes, move along
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
            child_str = node.treelike2(level+1, attr)
            if child_str:
                str += "{}{}".format("  "*(level+1), child_str)
        return str

    def fill_per_file(self, path):

        filepath = "{}{}/{}".format(MemTreeNode.abs_slash, self.full_name(), path)

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

                # Search every callsite in db matching this name
                for name, callsite in child.db.f.iteritems():
                    if name.startswith(m.group(2)):
                        child.funcs[name] = callsite

            m = re.match(r".*\s([0-9]+)\sOBJECT.*\s+([a-zA-Z0-9_\.]+)\b", line)
            if m:
                if m.group(2) in child.data:
                    print "[WARNING] Duplicate data entry! {}".format(m.group(2))
                child.data[m.group(2)] = int(m.group(1))

    # This is deprecated, fill_per_file should be used instead.
    # I keep it here just to have the code handy.
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
            pass
        else:
            node, others = parts
            if node not in self.childs:
                self.childs[node] = MemTreeNode(node, self)
            self.childs[node].add_child(others)


# Based on addr2sym.py
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

##########################################################################
##
## Main
##
##########################################################################

def main():

    parser = OptionParser()
    parser.add_option("-k", "--kernel",
                      dest="buildpath",
                      default="",
                      help="path to built kernel tree")

    parser.add_option("-f", "--file",
                      dest="file",
                      default="",
                      help="trace log file to analyze")

    parser.add_option("-b", "--start-branch",
                      dest="start_branch",
                      default="",
                      help="first directory name to use as ringchart root")

    parser.add_option("-r", "--rings-file",
                      dest="rings_file",
                      default="",
                      help="plot ringchart information")

    parser.add_option("-i", "--rings-show",
                      dest="rings_show",
                      action="store_true",
                      help="show interactive ringchart")

    parser.add_option("-a", "--rings-attr",
                      dest="rings_attr",
                      default="current_dynamic",
                      help="attribute to visualize [static, current, \
                                    current_dynamic, total_dynamic, waste]")

    parser.add_option("--malloc",
                      dest="do_malloc",
                      action="store_true",
                      help="trace kmalloc/kfree only")

    parser.add_option("--cache",
                      dest="do_cache",
                      action="store_true",
                      help="trace kmem_cache_alloc/kmem_cache_free only")

    parser.add_option("-c", "--account-file",
                      dest="account_file",
                      default="",
                      help="show output matching slab_account output")

    parser.add_option("-l", "--callers-file",
                      dest="callers_file",
                      default="",
                      help="show callers file suitable for ringchart generation")

    parser.add_option("-o", "--order-by",
                      dest="order_by",
                      default="current_dynamic",
                      help="attribute to order account \
                            [current_dynamic, total_dynamic, alloc_count, waste]")


    (opts, args) = parser.parse_args()

    # Kernel build path is a mandatory parameter.
    # We need to look at compiled objects and also for System.map.
    if opts.buildpath == "":
        print "Please set a kernel build path!"
        parser.print_help()
        return

    # Check valid options
    if len(opts.order_by) > 0:
        if opts.order_by not in dir(Callsite):
            print "Hey! {} is not a valid --order-by option".format(opts.order_by)
            parser.print_help()
            return

    if len(opts.rings_attr) > 0:
        if opts.rings_attr not in dir(MemTreeNodeSize):
            print "Hey! {} is not a valid --rings-attr option".format(opts.rings_attr)
            parser.print_help()
            return

    # Clean user provided kernel path from dirty slashes
    opts.buildpath = opts.buildpath.rstrip("/")

    # If we don't have a trace log file,
    # then we'll fallback to static report mode.
    if len(opts.file) == 0:
        print "No trace log file specified: will report on static size only"
        opts.rings_attr = "static"
        opts.do_malloc = False
        opts.do_cache = False
        opts.account_file = ""
        opts.with_rings = True
        opts.just_static = True
    else:
        opts.just_static = False

    if opts.rings_show is None:
        opts.rings_show = False

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
                rootDB.add_malloc("{}+{}".format(fun, offset),
                                  m.group(2),
                                  int(m.group(3)),
                                  int(m.group(4)), line)

            m = re.match(free_re, line)
            if m:
                rootDB.add_free(m.group(1))

    root_path = "{}/{}".format(opts.buildpath, opts.start_branch).rstrip("/")

    # Skip this directories when walking kernel build
    blacklist = ("scripts", "tools")

    # We need to specify if user provided buildpath is absolute
    if opts.buildpath.startswith("/"):
        MemTreeNode.abs_slash = "/"
    else:
        MemTreeNode.abs_slash = ""

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
            if filepath.endswith("built-in.o"):
                continue
            if filepath.endswith("vmlinux.o"):
                continue
            if filepath.endswith(".o"):
                # We need to check if this object file,
                # has a corresponding source file
                filesrc = "{}.c".format(path.splitext(filepath)[0])
                if path.exists(filesrc):
                    tree.add_child(filepath)

    print "Cleaning tree"
    tree = tree.get_clean()

    # DEBUG--ONLY. Should we add an option for this?
    #print(tree.treelike2(attr = opts.rings_attr))
    if len(opts.callers_file) != 0:
        print "Creating callers file at {}".format(opts.callers_file)
        rootDB.print_callers(opts.callers_file,
                             tree)


    if len(opts.account_file) != 0:
        print "Creating account file at {}".format(opts.account_file)
        rootDB.print_account(opts.account_file,
                             opts.order_by,
                             tree)

    if len(opts.rings_file) != 0 or opts.rings_show == True :
        if tree is None:
            print "Sorry, there is nothing to plot for branch '{}'".format(opts.start_branch)
        else:
            print "Creating ringchart for attribute '{}'".format(opts.rings_attr)
            visualize_mem_tree(tree, opts.rings_attr, opts.rings_file, opts.rings_show)


##########################################################################
##
## Visualization stuff
##
##########################################################################


CENTER_X = 1.0
CENTER_Y = 1.0
WIDTH = 0.2
tango_colors = ['#ef2929',
        '#ad7fa8',
        '#729fcf',
        '#8ae234',
        '#e9b96e',
        '#fcaf3e',]


def human_bytes(bytes, precision=1):
    """Return a humanized string representation of a number of bytes.

    Assumes `from __future__ import division`.

    >>> humanize_bytes(1)
    '1 byte'
    >>> humanize_bytes(1024)
    '1.0 kB'
    >>> humanize_bytes(1024*123)
    '123.0 kB'
    >>> humanize_bytes(1024*12342)
    '12.1 MB'
    >>> humanize_bytes(1024*12342,2)
    '12.05 MB'
    >>> humanize_bytes(1024*1234,2)
    '1.21 MB'
    >>> humanize_bytes(1024*1234*1111,2)
    '1.31 GB'
    >>> humanize_bytes(1024*1234*1111,1)
    '1.3 GB'
    """
    abbrevs = (
        (1<<50L, 'PB'),
        (1<<40L, 'TB'),
        (1<<30L, 'GB'),
        (1<<20L, 'MB'),
        (1<<10L, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    return '{0:.{1}f} {2}'.format(bytes / factor, precision, suffix)


class Section:
    def __init__(self, node, size, total_size, total_angle, start_angle):
        self.node = node
        self.size = size
        self.start_angle = start_angle
        self.angle = size * total_angle / total_size


def ring_color(start_angle, level):
    from matplotlib.colors import colorConverter

    # f:      [1 - 0.26]
    # rel:    [0 - 198]
    # icolor: [0 - 5]

    if level == 1:
        return colorConverter.to_rgb('#808080')

    f = 1 - (((level-1) * 0.3) / 8)
    rel = start_angle / 180. * 99
    icolor = int(rel / (100./3))
    next_icolor = (icolor + 1) % 6

    # Interpolate (?)
    color = colorConverter.to_rgb(tango_colors[icolor])
    next_color = colorConverter.to_rgb(tango_colors[next_icolor])
    p = (rel - icolor * 100./3) / (100./3)

    color = [f * (c - p * (c - n)) for c, n in zip(color, next_color)]

    return color


def create_child_rings(tree, level=2, level_angle=360, start_angle=0, rings=[],
         radius=WIDTH, center=(CENTER_X, CENTER_Y), size_attr="static"):

    from matplotlib.patches import Wedge

    child_size = 0
    max_size = getattr(tree.size(), size_attr)()

    if len(tree.childs) == 0:
        return rings

    if max_size == 0:
        for name, node in tree.childs.items():
            max_size += getattr(node.size(), size_attr)()
    if max_size == 0:
        return rings

    s_angle = start_angle
    sections = {}

    # Create child wedges
    for name, node in tree.childs.items():

        size = getattr(node.size(), size_attr)()
        s = Section(node, size, max_size, level_angle, s_angle)
        sections[name] = s

        create_child_rings(node, level+1, s.angle, s_angle, rings, radius, center, size_attr)
        s_angle += s.angle
        child_size += size

    # Just a check
    if child_size > max_size:
        print "[{}] Ooops, child size is greater than max size".format(name)

    for name, section in sections.items():

        # Create tuple: (wedge, name)
        name = "{} {}".format(name, human_bytes(section.size))
        tup = ( Wedge(center,
            level * radius,
            section.start_angle,
            section.start_angle + section.angle,
            width=radius,
            facecolor=ring_color(section.start_angle, level)),
            name)

        rings.append(tup)

    return rings


def visualize_mem_tree(tree, size_attr, filename, show):
    import pylab

    RING_MIN_WIDTH = 1
    TEXT_MIN_WIDTH = 5

    rings = create_child_rings(tree, size_attr=size_attr)

    fig = pylab.figure()
    ax = fig.add_subplot(111)
    annotations = []
    labels = []

    text = "{} {}".format(tree.name,
                          human_bytes(getattr(tree.size(), size_attr)()))
    ann = ax.annotate(text,
                      size=12,
                      bbox=dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8),
                      xy=(CENTER_X, CENTER_Y), xycoords='data',
                      xytext=(CENTER_X, CENTER_Y), textcoords='data')
    annotations.append(ann)

    for p in rings:
        wedge = p[0]

        # Skip if too small
        if (wedge.theta2 - wedge.theta1) < RING_MIN_WIDTH:
            continue

        # Add wedge
        ax.add_patch(wedge)

        # Skip text if too small
        if (wedge.theta2 - wedge.theta1) < TEXT_MIN_WIDTH:
            continue

        theta = math.radians((wedge.theta1 + wedge.theta2) / 2.)
        x0 = wedge.center[0] + (wedge.r - wedge.width / 2.) * math.cos(theta)
        y0 = wedge.center[1] + (wedge.r - wedge.width / 2.) * math.sin(theta)
        x = wedge.center[0] + (0.1 + wedge.r * 1.5 - wedge.width / 2.) * math.cos(theta)
        y = wedge.center[1] + (0.1 + wedge.r * 1.5 - wedge.width / 2.) * math.sin(theta)

        ax.plot(x0, y0, ".", color="black")

        text = p[1]
        ann = ax.annotate(text,
                    size=12,
                    bbox=dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8),
                    xy=(x0, y0), xycoords='data',
                    xytext=(x, y), textcoords='data',
                    arrowprops=dict(arrowstyle="-", connectionstyle="angle3, angleA=0, angleB=90"),)
        annotations.append(ann)

    (alloc, req) = tree.db.get_bytes()

    pylab.axis('off')

    if len(filename) != 0:
        print("Plotting to file '{}'".format(filename))
        pylab.savefig("{}".format(filename),
                      bbox_extra_artists=annotations,
                      bbox_inches='tight', dpi=300)
    if show:
        print("Plotting interactive")
        pylab.show()


##########################################################################

if __name__ == "__main__":
    main()
