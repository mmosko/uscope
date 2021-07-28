#!/usr/bin/python
import sys
import networkx as nx
from networkx.drawing.nx_pydot import write_dot
import subprocess
import math
import re
import random
import os
from collections import defaultdict
import copy
from enum import Enum

# This class represents a CAPMAP graph. This file contains the logic
# for loading in a .cmap file (or multiple .cmap files), parsing the
# debugging metadata and instruction counts from a matching vmlinux,
# as well as some other operations on the resulting CAPMAP objects.
#
# In the directory in which a vmlinux is stored, it automatially
# checks for a vmlinux_plain file which should be a kernel compiled
# without memorizer. This file is optional but used for accurate
# instruction counts.
#
# If the .cmap file also has a .funcs file or a .baseline file, these
# are optionally read in as function counts and baseline cycles for
# future scaling and overhead calculations.
#
# The first time a .cmap file is loaded, it will automatically be
# compressed into a .cmap.comp file. In future loads, these will
# automatically be detected and loaded instead. This saves a
# tremendous amount of time.
#
# Lots of this file was added bit-by-bit to handle increasing
# complexity as research progressed, some larger refactoring would be
# good now that scope is more known.

# List of operations in uSCOPE; used by this file and others
ops = ["read", "write", "call", "return", "free"]

# Size of instruction for default case
INSTR_SIZE = 4

#### Some classes for CAPMAP graph objects ####

# There are two kinds of nodes in CAPMAP graph
class NodeType(Enum):
    OBJECT = 1
    SUBJECT = 2
    
# Instruction nodes have an InstrType
class InstrType(Enum):
    READ = 1
    WRITE = 2
    CALL = 3
    RETURN = 4
    FREE = 5

# Object nodes have a MemType
class MemType(Enum):
    HEAP = 1
    GLOBAL = 2
    SPECIAL = 3
    
# CAPMAP represented as a digraph. Nodes are either:
#   - A kernel object, as denoted by the tuple of (NodeType.OBJECT, MemType, alloc_ip)
#   - An instruction, denoted by the tuple (NodeType.SUBJECT, instruction_type, access_ip)
# This class reads in a .cmap file and creates a CAPMAP object containing a networkx graph.
class CAPMAP:

    # Init function does the following operations in this order:
    # 1) It extracts info from the vmlinux using "nm", "objdump", etc
    # 2) It parses a single cmap file or a whole directory of cmap files
    # 3) It does some post-processing and cleaning to create final CAPMAP object
    def __init__(self, vmlinux, kmap_file, verbose=False, import_maps_from = None):

        ### Define some class variables ###
        self.vmlinux = vmlinux
        self.has_plain_vmlinux = False
        self.re_kernel = re.compile('.*/linux[a-z\-]*/(.*)$')
        self.kmap_file = kmap_file
        self.kmap_name = os.path.basename(self.kmap_file)
        self.kmap_dir = os.path.dirname(self.vmlinux)
        self.symbol_table = {}
        self.symbol_table_sizes = {}
        self.symbol_table_names = {}
        self.symbol_table_src_files = {}
        self.global_table_sizes = {}
        self.global_table_names = {}
        self.global_table_src_files = {}
        self.object_names = {}
        self.verbose = verbose
        self.global_objs = set()
        self.functions = set()
        self.function_line_numbers = {}
        self.live_functions = set()
        self.instr_count_map = {}
        self.instr_count_map_plain = {}
        self.dg = nx.DiGraph();
        self.addr_list = set()
        self.return_map = {}
        self.capmap_object_sizes = {}
        self.number_calls = 0
        self.number_returns = 0
        self.baseline_cycles = None
        self.clear_maps()

        print("Creating CAPMAP object...")        
        ### Extract info about vmlinux ###

        # Creates symbol_table and global_table dictionaries
        self.load_symbol_table()

        # Get function sizes from plain vmlinux if we have one        
        self.get_sizes_from_plain()
        
        # Parse instructions from vmlinux, create the ip_to_file and related maps
        self.read_instructions_and_get_info()

        ### Parse cmap file(s) ###
        
        # If passed a specific cmap file, load that file.
        # If passed a directory, iterate over all cmaps in that directory.
        if os.path.isfile(kmap_file):
            print("\tLoading from one file: " + kmap_file)
            self.from_single_file = True
            self.parse_to_digraph(kmap_file)

            # In the single file case, we also check for baseline cycles file
            baseline_file = os.path.basename(kmap_file).split(".")[0] + ".baseline"
            baseline_path = os.path.join(os.path.dirname(kmap_file), baseline_file)
            if os.path.exists(baseline_path):
                f = open(baseline_path)
                self.baseline_cycles = int(f.readline())
                print("\tThis CAPMAP had a baseline cycles of " + str(self.baseline_cycles))
        else:
            print("\tLoading all CAPMAPs in dir: " + kmap_file)
            self.from_single_file = False
            files = set()
            for fname in sorted(os.listdir(kmap_file)):
                # Find the .cmap and .cmap.comp files
                if fname[-5:] == ".cmap":
                    files.add(fname[:-5])
                if fname[-5:] == ".comp":
                    files.add(fname[:-10])
            files = sorted(files)
            for fname in files:
                self.parse_to_digraph(kmap_file + "/" + fname + ".cmap")
            # Set the size of an object to the average across all capmaps
            self.set_average_sizes()

        ### Post processing ###

        self.sanity_check_op_counts()
        self.build_object_ownership_maps()
        self.scale_capmap()
        self.calc_live_functions()
        self.report_stats()

        # Create a privilege CAPMAP file output if passed a third argument (name of output)
        if len(sys.argv) > 3:
            print("\tMaking special capmaps from this run, putting in: " + sys.argv[3])
            if not os.path.exists(sys.argv[3]):
                os.mkdir(sys.argv[3])
            self.create_special_capmaps(sys.argv[3])

        # Import_maps_from is an optimization for saving memory
        # It allows one CAPMAP to reuse metadata maps from another CAPMAP
        if import_maps_from != None:

            # Make a pointer to these
            self.ip_to_file = import_maps_from.ip_to_file
            self.ip_to_func = import_maps_from.ip_to_func
            self.ip_to_dir = import_maps_from.ip_to_dir
            self.ip_to_topdir = import_maps_from.ip_to_topdir
            self.ip_to_mono = import_maps_from.ip_to_mono
            self.ip_to_ip = import_maps_from.ip_to_ip
            self.func_to_file = import_maps_from.func_to_file
            self.func_to_func = import_maps_from.func_to_func
            self.func_to_dir = import_maps_from.func_to_dir
            self.func_to_topdir = import_maps_from.func_to_topdir
            self.func_to_mono = import_maps_from.func_to_mono
            self.file_to_funcs = import_maps_from.file_to_funcs            
            self.file_to_dir = import_maps_from.file_to_dir
            self.file_to_topdir = import_maps_from.file_to_topdir
            self.obj_no_cluster = import_maps_from.obj_no_cluster
            self.obj_owner_func = import_maps_from.obj_owner_func
            self.obj_owner_file = import_maps_from.obj_owner_file
            self.obj_owner_dir = import_maps_from.obj_owner_dir
            self.obj_owner_topdir = import_maps_from.obj_owner_topdir
            self.symbol_table = import_maps_from.symbol_table
            self.symbol_table_sizes = import_maps_from.symbol_table_sizes
            self.symbol_table_names = import_maps_from.symbol_table_names
            self.symbol_table_src_files = import_maps_from.symbol_table_src_files
            self.global_table_sizes = import_maps_from.global_table_sizes
            self.global_table_names = import_maps_from.global_table_names
            self.global_table_src_files = import_maps_from.global_table_src_files

            # Clear these out
            self.global_objs = set()
            self.functions = set()
            self.live_functions = set()
            self.instr_count_map = {}
            self.instr_count_map_plain = {}
            self.addr_list = set()
            self.return_map = {}

        print("Done creating CAPMAP!")

    # Helper function for clearing class variables
    def clear_maps(self):
        self.ip_to_file = {}
        self.ip_to_func = {}
        self.ip_to_dir = {}
        self.ip_to_topdir = {}        
        self.ip_to_mono = {}
        self.ip_to_ip = {}        
        self.func_to_file = {}        
        self.func_to_func = {}        
        self.func_to_dir = {}
        self.func_to_topdir = {}
        self.func_to_mono = {}
        self.file_to_funcs = {}
        self.file_to_dir = {}
        self.file_to_topdir = {}
        self.obj_no_cluster = {}
        self.obj_owner_func = {}
        self.obj_owner_file = {}
        self.obj_owner_dir = {}
        self.obj_owner_topdir = {}

    # This is the core logic for reading in a .cmap file. It has been
    # growing steadily to handle increasing complexity in Memorizer
    # data, it should probably be refactored.  Reads a .cmap file and
    # creates a networkx graph.
    def parse_to_digraph(self, fn):

        # Check to see if there is already a compressed form of this CAPMAP
        found_compressed = False
        if os.path.isfile(fn + ".comp"):
            found_compressed = True
            fn += ".comp"

        # Or if we were directly passed a compressed CAPMAP
        if fn[-4:] == "comp":
            found_compressed = True

        # Parse this cmap file into a local graph this_dg.
        this_dg = nx.DiGraph()
        num_instr = 0
        num_obj = 0

        # Create data structure that tracks instance alloc/free time so that we can compute
        # max/average live if we want to use that kind of sizing model.
        # Index is object_addr, contains list of (alloc_time, free_time, size)
        instance_store = {}
        
        # Open .cmap file, process line by line
        with open(fn, "r") as file:

            # Track the current object
            obj = None

            for line in file:

                # Skip comments
                if line[0] == "#":
                    continue

                # Break line into fields
                myline = line.strip().split(',')

                # Lines with 10 fields are objects, with lines below them accesses to those objs
                if len(myline) == 10:

                    # Parse fields
                    alloc_ip = myline[0].strip()
                    alloc_pid = myline[1].strip()
                    va = myline[2].strip()
                    size = int(myline[3].strip())
                    alloc_time = int(myline[4].strip())
                    free_time = int(myline[5].strip())
                    free_ip = myline[6].strip()
                    allocator = myline[7].strip()
                    process = myline[8].strip()
                    slab_cache = myline[9].strip().split("(")[0] # Strip down to just slab name
                    name = None

                    # Handle a bug from Memorizer: huge free_time is invalid / not freed
                    if free_time > 100000000000:
                        free_time = 0

                    # Skip kernel modules
                    if alloc_ip[0:9] == "ffffffffa":
                        obj = None
                        continue

                    # We now prepare an object_addr and memtype for this object.
                    # Top-level parsing logic switches based on the allocator for
                    # this object:

                    # 1) Parse heap objects
                    if allocator in ["KMALLOC", "KMALLOC_ND", "KMEM_CACHE",
                                     "KMEM_CACHE_ND", "ALLOC_PAGES"]:

                        # There is a blank object of each kind, skip over them
                        if "null" in alloc_ip:
                            obj = None
                            continue
                        
                        object_addr = alloc_ip
                        memtype = MemType.HEAP

                        # Update instance store for max/average live calculations
                        valid_free = free_ip[0:9] == "ffffffff8" and free_time != 0

                        # Handle loading prealloced objects in the compressed format
                        if alloc_ip[0:10] == "prealloced":
                            memtype = MemType.SPECIAL
                            object_addr = alloc_ip
                        
                        # Handle preallocated objects
                        if alloc_ip == "feedbeef":
                            object_addr = "prealloced-" + slab_cache
                            memtype = MemType.SPECIAL

                        # Set name for heap objects. Some sentinal values e.g.
                        if "feedbeef" in alloc_ip or "prealloced" in alloc_ip:
                            name = allocator + "_prealloced_" + slab_cache
                        else:
                            name = allocator + "_" + self.ip_to_func[alloc_ip]
                        
                        if found_compressed == False and alloc_time != 0 and valid_free:
                            if not object_addr in instance_store:
                                instance_store[object_addr] = []
                            instance_store[object_addr].append((alloc_time, free_time, size))

                    # 2) Parse global objects
                    elif allocator in ["GLOBAL", "UFO_GLOBAL"]:

                        # Attempt to salvage UFO globals if possible
                        if allocator == "UFO_GLOBAL":
                            if va in self.symbol_table:
                                symbol_addr = self.symbol_table[va]
                                symbol_name = self.symbol_table_names[symbol_addr]
                                #print("identified UFO global! Was " + symbol_name + " at " + symbol_addr + " that has full size " + str(self.symbol_table_sizes[symbol_addr]))
                                #print("Access size was " + str(size))
                                object_addr = symbol_addr
                                size = self.symbol_table_sizes[symbol_addr]
                            else:
                                object_addr = va
                        else:
                            object_addr = va
                        
                        memtype = MemType.GLOBAL
                        self.global_objs.add(object_addr)

                        # Set name for globals
                        if va in self.symbol_table_names:
                            name = "GLOBAL_" + self.symbol_table_names[va]
                        elif va in self.global_table_names:
                            name = "GLOBAL_" + self.global_table_names[va]
                        else:
                            name = "GLOBAL_anon"

                    # 3) Parse stack pages
                    elif allocator == "STACK_PAGE":
                        
                        # There is one stack with size 0 in each cmap. Give it 32768
                        # I think this is per cpu-stack vs thread stack?
                        if size == 0:
                            size = 32768
                        
                        # Remove a few invalidly freed stacks in current data
                        # After loading compressed form, just take alloc_ip as addr
                        add_to_store = True                        
                        if found_compressed == False:
                            if free_time == 0 or "deadbeef" in free_ip:
                                add_to_store = False
                            object_addr = "THREAD_STACK"
                        else:
                            object_addr = alloc_ip

                        memtype = MemType.SPECIAL # Treated as special

                        name = "STACK_PAGE"

                        # Update instance store for max/average live calculations
                        if found_compressed == False and alloc_time != 0 and add_to_store:
                            if not object_addr in instance_store:
                                instance_store[object_addr] = []
                            instance_store[object_addr].append((alloc_time, free_time, size))

                    # After heap, globals, and stacks we have the special kinds of memory

                    # 4) Parse MEMBLOCK objects
                    elif allocator in ["UFO_MEMBLOCK", "MEMBLOCK"]:
                        object_addr = "MEMBLOCK"
                        name = "MEMBLOCK"
                        memtype = MemType.SPECIAL

                    # 5) Parse vmalloc() objects
                    elif allocator == "VMALLOC":
                        object_addr = alloc_ip
                        name = "VMALLOC_" + alloc_ip
                        memtype = MemType.SPECIAL

                    # 6) UFOs that are in the VMEM region are VMEM objects
                    elif allocator == "UFO_NONE" and va[0:6] == "ffffea":
                        object_addr = "VMEMMAP"
                        name = "VMEMMAP"
                        memtype = MemType.SPECIAL

                    # 7) Parse FIXMAP (only in compressed)
                    elif alloc_ip in ["FIXMAP"]:
                        object_addr = alloc_ip
                        name = "FIXMAP"
                        memtype = MemType.SPECIAL
                        
                    # 8) Parse code (only in compressed)
                    elif alloc_ip[0:5] == "code_":
                        object_addr = alloc_ip
                        name = "CODE_" + alloc_ip
                        memtype = MemType.SPECIAL

                    # 9) The grab bag:
                    # What's left are one missing memblock region, a few things we can salvage from globals,
                    # and true anonymous objects.
                    elif allocator == "UFO_NONE" or allocator == "UFO_HEAP":

                        # There is one memblock region that is not being detected by Memorizer. Not sure if happens too early,
                        # or if we are missing a hook. I noticed that it's related to BIOS, so plausible it runs before Memorizer
                        # hooks it.                        
                        va_int = int(va, 16) if va[0:4] == 'ffff' else None
                        if va_int != None and (va_int >= 0xffff880000002000 and va_int < 0xffff880000010000):
                            object_addr = "MEMBLOCK"
                            name = "MEMBLOCK"
                            memtype = MemType.SPECIAL
                        # Some UFOs can be salvaged into real objects based on the symbol table:
                        elif va in self.symbol_table:
                            symbol_addr = self.symbol_table[va]
                            symbol_name = self.symbol_table_names[symbol_addr]
                            object_addr = symbol_addr
                            size = self.symbol_table_sizes[symbol_addr]
                            memtype = MemType.GLOBAL
                            name = "GLOBAL_" + symbol_name
                        # We do actually get some memory accesses to CODE (e.g., dynamic rewriting) so capture those as small objects now
                        elif va_int != None and (va_int >= 0xffffffff80000000 and va_int < 0xffffffff9fffffff):
                            object_addr = "code_" + va
                            name = "CODE_" + va
                            memtype = MemType.SPECIAL
                        # There's a special region of memory for FIXADDR objects, we just group them all as one object
                        elif va_int != None and (va_int >= 0xffffffffff578000 and va_int < 0xffffffffff5fffff):
                            object_addr = "FIXMAP"
                            name = "FIXMAP"
                            memtype = MemType.SPECIAL                            
                        else:
                            # Now separating ANON into its two types
                            if "UFO_NONE" in allocator:
                                object_addr = "ANON_NONE"
                                #print("ANON NONE:")
                                #print(str(line))
                            else:
                                object_addr = "ANON_HEAP"
                                #print("ANON HEAP:")
                                #print(str(line))
                            name = "ANON"   
                            memtype = MemType.SPECIAL

                    # A few fallback/debugging objects. Should have no accesses.
                    elif allocator in ["STACK", "GEN_HEAP", "INDUCED_ALLOC",
                                       "BOOTMEM", "MEMORIZER", "USER", "BUG", "NONE"]:
                        object_addr = allocator
                        name = "INVALID_" + allocator
                        memtype = MemType.SPECIAL

                    # Catch-all for allocator field
                    else:
                        print("Error:")
                        print(str(line))                        
                        raise Exception("Failed to parse object. Allocator was: " + allocator)

                    self.object_names[object_addr] = name
                    
                    # Construct the graph node for this object.
                    # Depending on how much context we want, can use various definitions of an obj
                    # obj = (NodeType.OBJECT, memtype, object_addr, size, alloc_pid)
                    # obj = (NodeType.OBJECT, memtype, object_addr, size)
                    # obj = (NodeType.OBJECT, memtype, object_addr)
                    obj = (NodeType.OBJECT, memtype, object_addr)

                    # Now add object and update the size depending on the size model.

                    # Add new object node if not in graph. Easy case.
                    if not this_dg.has_node(obj):
                        this_dg.add_node(obj, size=size, allocator=allocator,va=va, slab_cache=slab_cache, name=name, weight=[1,1,1])
                        num_obj += 1
                    else:
                        # The size of VMEMMAP will be the sum of all the component UFOs.
                        # Same for MEMBLOCK and ANONs, so these are a special case for object sizing.
                        if object_addr in ["VMEMMAP", "MEMBLOCK", "ANON", "ANON_NONE", "ANON_HEAP", "FIXADDR"]:
                            this_dg.node[obj]["size"] += size

                        # Update the stored value to largest instance.
                        # Max live calculation happens later, so this is only for max_instace.
                        if memtype == MemType.HEAP or allocator == "VMALLOC":
                            if size > this_dg.node[obj]["size"]:
                                this_dg.node[obj]["size"] = size

                    # Now, if this obj has a valid free_ip, we will add the free edge too.
                    # This involves creating a new instruction node, and adding the edge to
                    # the object we just added.
                    if not ("null" in free_ip or "deadbeef" in free_ip):

                        # First, add the instruction node for the free instr
                        free_node  = (NodeType.SUBJECT, free_ip)
                        if not this_dg.has_node(free_node):
                            this_dg.add_node(free_node, size=INSTR_SIZE)

                        # Next, add or update the edge.
                        if (not this_dg.has_edge(free_node, obj)):
                            this_dg.add_edge(free_node, obj,
                                             write = 0, read = 0,
                                             call = 0,free = 1)

                            # Have to add this way, "return" is a Python keyword
                            this_dg.get_edge_data(free_node, obj)["return"] = 0

                        else:
                            edge = this_dg.get_edge_data(free_node, obj)
                            edge["free"] += 1
                    

                # Lines with 3 fields and begin with a space are accesses to last obj
                elif len(myline) > 2 and line[0] == " ":

                    # Skip accesses to obj if none object
                    if obj == None:
                        raise Exception("Access to None obj. Access=" + str(line))
                    
                    instr_ip = myline[0].strip()
                    #access_pid = myline[1] no longer in .cmap
                    writes = int(myline[1])
                    reads = int(myline[2])

                    # Skip kernel modules
                    if instr_ip[0:9] == "ffffffffa":
                        continue

                    # Skip when instr_ip is invalid, some bug introduced this
                    if int(instr_ip, 16) < (1 << 10):
                        continue
                    
                    frees = 0
                    if found_compressed == True:
                        frees = int(myline[3])
                        if frees > 1e10:
                            raise Exception("Loaded more than 1e10 frees. Probably misinterpreted addr or timestamp as count.")
                    
                    # Again, can use various definitions of an access node depending on context
                    #access_from  = (NodeType.SUBJECT, instr_type, instr_ip, access_pid)
                    access_from  = (NodeType.SUBJECT, instr_ip)

                    if (not this_dg.has_node(access_from)):
                        this_dg.add_node(access_from, size=INSTR_SIZE)
                        num_instr += 1  

                    # Add new edge or add weights to existing edge
                    if (not this_dg.has_edge(access_from, obj)):
                        this_dg.add_edge(access_from, obj,
                                         write = writes, read = reads,
                                         call = 0,free = frees)

                        # Have to add this way, "return" is a Python keyword
                        this_dg.get_edge_data(access_from, obj)["return"] = 0

                    else:
                        edge = this_dg.get_edge_data(access_from, obj)
                        edge["read"] += reads
                        edge["write"] += writes
                        edge["call"] += 0
                        edge["return"] += 0
                        edge["free"] += frees

                # Lines with only 3 fields are call/ret
                else:

                    # Should unify delimiters, right now cfg are space separated
                    if len(myline) == 1:
                        myline = myline[0].split(" ")

                    # These are now stored in the correct order (from, to) so parse like this:
                    from_addr = myline[0]
                    to_addr = myline[1]
                    call_count = int(myline[2])

                    # Skip kernel modules
                    if to_addr[0:9] == "ffffffffa" or from_addr[0:9] == "ffffffffa":
                        continue

                    # Check if source instr is in CAPMAP, if not then add
                    src_node  = (NodeType.SUBJECT, from_addr)
                    if not this_dg.has_node(src_node):
                        this_dg.add_node(src_node, size=INSTR_SIZE)

                    # Check if dest instr is in CAPMAP, if not then add
                    dst_node  = (NodeType.SUBJECT, to_addr)
                    if not this_dg.has_node(dst_node):
                        this_dg.add_node(dst_node, size=INSTR_SIZE)

                    # Add this call edge
                    if not this_dg.has_edge(src_node, dst_node):
                        this_dg.add_edge(src_node, dst_node, write = 0, read = 0,
                             call = call_count,free = 0)
                        this_dg.get_edge_data(src_node, dst_node)["return"] = 0
                        self.number_calls += 1

        # Special case VMEMMAP: after parsing, scale to remove size from Memorizer data
        if found_compressed == False:
            for obj_node in this_dg:
                if obj_node[0] != NodeType.OBJECT:
                    continue
                obj_addr = self.get_node_ip(obj_node)
                if obj_addr == "VMEMMAP":
                    old_size = this_dg.node[obj_node]["size"]
                    new_size = int(old_size * (8.0 / 124.0))
                    print("Scaling down VMEMMAP entry. Old_size=" + str(old_size) + " new size=" + str(new_size))
                    this_dg.node[obj_node]["size"] = new_size
                        

        # We're now done parsing all the lines in the .cmap file.
        # We now go through and recompute object sizes for average_live
        if found_compressed == False:
            print("Heap scheme is max_live, calculating now.")
            for obj_addr in instance_store:

                # Find the object node in the graph
                if obj_addr in ["STACK_PAGE", "THREAD_STACK", "PER_CPU_STACK"] or obj_addr[0:10] == "prealloced":
                    memtype = MemType.SPECIAL
                else:
                    memtype = MemType.HEAP
                obj_node = (NodeType.OBJECT, memtype, obj_addr)

                # Calculate max live
                object_size = self.compute_dynamic_obj_size(instance_store[obj_addr], obj_addr)

                # Special case, per cpu stacks have no free time but we add up their sizes
                # Size was stored as third element of tuple, sum those up
                if obj_addr == "PER_CPU_STACK":
                    object_size = sum([i[2] for i in instance_store[obj_addr]])

                # Update object
                this_dg.node[obj_node]["size"] = object_size

        # Add any misaligned addresses into our maps
        self.fix_misaligned_instructions(this_dg)        

        # Remove KASAN / Memorizer data from graph
        self.remove_invalid_CAPMAP_entries(this_dg, fn)

        # Add returns back from forward call edges
        self.add_returns(this_dg)        

        # Add this graph onto running total
        self.add_capmap(this_dg, fn, found_compressed)

        # Add these object sizes onto capmap_object_sizes list. If we load
        # multiple capmaps, set object to the average across the capmaps.
        for node in this_dg:
            if node[0] == NodeType.OBJECT:
                objaddr = self.get_node_ip(node)
                # Skip globals
                if objaddr in self.symbol_table or objaddr in self.global_table_names:
                    continue
                if not objaddr in self.capmap_object_sizes:
                    self.capmap_object_sizes[objaddr] = []
                self.capmap_object_sizes[objaddr].append(this_dg.node[node]["size"])

        # Lastly, make a compressed CAPMAP if we didn't already have one
        if found_compressed == False:
            print("Making compressed.")
            self.make_compressed_capmap(this_dg, fn)

    # Extract the symbol table from the vmlinux using "nm", populate the symbol_table dictionaries.
    # Also load in global_table.txt if we have one; some symbols are not in vmlinux.
    def load_symbol_table(self):

        print("\tLoading symbol table from vmlinux...")

        # Load global_table.txt if we have it
        global_table_file = self.kmap_dir + "/global_table.txt"
        self.global_table_database = {}
        if os.path.isfile(global_table_file):
            gt_file = open(global_table_file, "r")
            for line in gt_file:
                line = line.split()
                if len(line) <= 2:
                    continue
                addr = line[0]
                size = line[1]
                name = line[2]
                src = line[3]
                if "/" in src:
                    src = "".join(self.re_kernel.findall(src))                
                self.global_table_names[addr] = name
                self.global_table_sizes[addr] = size
                self.global_table_src_files[addr] = src
        else:
            print("\tWarning: Did not find global_table.txt. Object metadata will be incomplete.")
        
        # Dump symbol table using nm
        nm_output = self.vmlinux + ".nm"
        if not os.path.isfile(nm_output):
            os.system("nm " + self.vmlinux + " -l -S -v  > " + nm_output)

        # Parse nm output and store into symbol table dictionaries
        # Lines look like:
        # ffffffff06480000 A init_per_cpu__gdt_page
        # ffffffff83671000 0000000000001000 B idt_table
        with open(nm_output) as fh:
            addr = ""
            last_addr = ""
            symbol_kind = ""
            size = ""
            src = ""
            last_unterminated = False
            
            for line in fh:

                # Break line into fields
                line = line.strip()
                parts = line.split()
                addr = parts[0]

                # Skip some initial strange symbols with invalid addresses
                if addr[0] == "0":
                    continue

                # If last symbol had start addr but no end address, fill in gap with that value. Use name, src, size, etc
                # from the last extracted symbol.
                if last_unterminated:

                    # There are a few cases where we don't interpret this as a valid end-of-unterminated block
                    # Extract this symbol kind
                    if len(parts[2]) == 1:
                        this_symbol_kind = parts[2].capitalize()
                    if len(parts[1]) == 1:
                        this_symbol_kind = parts[1].capitalize()

                    # Exit it if not valid next thing
                    if not this_symbol_kind in ["R", "B", "D"]:
                        last_unterminated = False
                        continue

                    # The last entry goes from the last beginning address to this beginning address
                    #print("Painting from " + last_addr + " to " + addr + " with " + name + "|" + src + "|" + this_symbol_kind)
                    for paint_addr in range(int(last_addr,16), int(addr, 16)):
                        paint_addr = hex(paint_addr)[2:-1]
                        self.symbol_table[paint_addr] = last_addr

                    # Populate size for this entry
                    self.symbol_table_sizes[last_addr] = int(addr, 16) - int(last_addr, 16)
                    self.symbol_table_names[last_addr] = name + "|" + this_symbol_kind
                    self.symbol_table_src_files[last_addr] = src

                # Parse a few different cases
                if len(parts) in [4,5] and len(addr) == 16 and len(parts[1]) == 16 and len(parts[2]) == 1:
                    size = parts[1]
                    symbol_kind = parts[2].capitalize()

                    # We only care about these three for globals:
                    if not symbol_kind in ["R", "B", "D"]:
                        continue

                    # We got a valid global, add it to our database
                    name = parts[3]
                    if len(parts) == 5:
                        src = parts[4].split(":")[0] # Chop off line number
                    else:
                        src =""
                    last_unterminated = False
                    last_addr = addr

                # No size, set last_unterminated=True and assume size goes to next addr
                elif len(parts) in [3,4] and len(addr) == 16 and len(parts[1]) == 1:
                    symbol_kind = parts[1].capitalize()
                    if not symbol_kind in ["R", "B", "D"]:
                        continue
                    size = None
                    name = parts[2]
                    src = ""
                    if len(parts) == 4:
                        src = parts[3].split(":")[0] # Chop off line number
                    last_unterminated = True
                    last_addr = addr
                else:
                    continue

                if "/" in src:
                    src = "".join(self.re_kernel.findall(src))

                # If we made it here (and didn't hit the unterminated case) add to data structures
                if last_unterminated == False:
                    # Skip making maps for Memorizer data structures which are huge and not needed
                    if name in ["mem_events_wq_data", "memblock_events", "l2_tbl_pool",
                                "l1_tbl_pool", "kobj_l3_tbl", "stack_table"]:
                        continue
                    for paint_addr in range(int(addr,16), int(addr, 16) + int(size, 16)):
                        paint_addr = hex(paint_addr)[2:-1]
                        self.symbol_table[paint_addr] = addr

                    # Populate size for this entry
                    self.symbol_table_sizes[addr] = int(size, 16)
                    self.symbol_table_names[addr] = name + "|" + symbol_kind
                    self.symbol_table_src_files[addr] = src

    # This function looks for a vmlinux_plain file in the same location that vmlinux
    # is located. If found, it extracts function sizes and instruction counts from the
    # the plain vmlinux for more accurate instruction counting.
    def get_sizes_from_plain(self):

        if not os.path.isfile(self.vmlinux + "_plain"):
            print("\tWarning: no plain vmlinux found. Code sizes will be inaccurate.")
            return

        vmlinux_plain = self.vmlinux + "_plain"
        print("\tFound plain vmlinux. Extracting function sizes.")
        self.has_plain_vmlinux = True

        asm_output = vmlinux_plain + ".asm"
        if not os.path.isfile(asm_output):
            os.system("objdump -d " + vmlinux_plain + " > " + asm_output)

        # Read .asm once to collect all functions
        self.addr_list = set()
        with open(asm_output) as fh:
            for line in fh:
                line = line.strip()
                if line == "":
                    continue
                # This is the section that follows the .text section, so we end here
                if "section .altinstr" in line:
                    break
                if ">:" in line:
                    addr = line.split()[0]
                    self.addr_list.add(addr)
                    continue

        # Get info about all the functions
        self.batch_get_info(plain=True, follow_inline=False)

        # Parse the plain assembly file, count function sizes and instr counts
        with open(asm_output) as fh:
            current_func = None
            for line in fh:
                line = line.strip()

                if "section .altinstr" in line:
                    break
                
                if (line == "") or ("Disassembly" in line) or ("..." in line):
                    current_func = None
                    continue
                
                if ">:" in line:
                    addr = line.split()[0]
                    current_func = self.ip_to_func[addr]
                    if not current_func in self.instr_count_map_plain:
                        self.instr_count_map_plain[current_func] = {}
                        self.instr_count_map_plain[current_func]["size"] = 0
                        self.instr_count_map_plain[current_func]["total"] = 0
                    continue
                                    
                if current_func != None:
                    line_chunks = line.split("\t")
                    instr_bytes = line_chunks[1].strip()
                    num_bytes = len(instr_bytes.split())
                    self.instr_count_map_plain[current_func]["size"] += num_bytes
                    self.instr_count_map_plain[current_func]["total"] += 1
        
    # This function extracts lots of info from the vmlinux.
    #
    # It calls objdump on the vmlinux and parses through the asm file.
    # The main output of this function is the self.instr_count_map,
    # which contains the number of read/write/call/return/free instructions
    # in each function, as well as the self.ip_to_X which maps debug info
    # to instruction addresses.
    #
    # Additionally, this function creates the self.return_map which is a set
    # of return instructions inside each function. Used later for creating
    # return edges.
    def read_instructions_and_get_info(self):

        vmlinux = self.vmlinux
        
        print("\tExtracting info from " + vmlinux + ". This takes a few minutes...")

        # Reset the maps, which may have been populated with info from the plain vmlinux
        self.ip_to_func = {}
        self.ip_to_file = {}
        self.ip_to_ip = {}
        self.ip_to_dir = {}
        self.ip_to_topdir = {}
        self.ip_to_mono = {}
        self.func_to_func = {}
        self.func_to_file = {}
        self.func_to_dir = {}
        self.func_to_topdir = {}
        self.func_to_mono = {}
        self.file_to_dir = {}
        self.file_to_topdir = {}
        
        asm_output = vmlinux + ".asm"
        if not os.path.isfile(asm_output):
            os.system("objdump -d " + vmlinux + " > " + asm_output)

        # Read .asm once to collect all functions
        self.addr_list = set()
        with open(asm_output) as fh:
            for line in fh:
                line = line.strip()
                if line == "":
                    continue
                # This is the section that follows the .text section, so we end here
                if "section .altinstr" in line:
                    break
                if ">:" in line:
                    addr = line.split()[0]
                    self.addr_list.add(addr)
                    continue
                    
        # Get info about all the functions
        self.batch_get_info(plain=False, follow_inline=False)

        # Read through the .asm a second time.
        # Construct mappings for each instruction to func, file, dir, etc
        # Also record number of operations of each type in each function
        # (removed) Lastly, try to associate globals
        addr_extract = re.compile('[0-9a-f]{16}[ ,]')     
        with open(asm_output) as fh:
            
            funcname = None
            filename = None
            dirname = None
            topdirname = None
            
            for line in fh:
                line = line.strip()

                # This is the section that follows the .text section, so we end here
                if "section .altinstr" in line:
                    break                
                
                # Each new function, lookup metadata from addr2line
                if ">:" in line:
                    addr = line.split()[0]
                    funcname = self.ip_to_func[addr]
                    filename = self.ip_to_file[addr]
                    dirname = self.ip_to_dir[addr]
                    topdirname = self.ip_to_topdir[addr]
                    self.functions.add(funcname)

                    if not funcname in self.instr_count_map:
                        self.instr_count_map[funcname] = {}
                        self.instr_count_map[funcname]["total"] = 0
                        self.instr_count_map[funcname]["size"] = 0                        
                        self.instr_count_map[funcname]["read"] = 0
                        self.instr_count_map[funcname]["write"] = 0                        
                        self.instr_count_map[funcname]["call"] = 0
                        self.instr_count_map[funcname]["return"] = 0
                        self.instr_count_map[funcname]["free"] = 0                        
                    continue

                if line == "":
                    funcname = None
                    continue
                
                if funcname != None:

                    # Store info about this isntr                    
                    addr = line.split()[0][:-1]
                    self.ip_to_mono[addr] = "mono"
                    self.ip_to_topdir[addr] = topdirname
                    self.ip_to_dir[addr] = dirname
                    self.ip_to_file[addr] = filename
                    self.ip_to_func[addr] = funcname
                    self.ip_to_ip[addr] = addr

                    # Skip fentry calls.
                    if "__fentry__" in line:
                        continue

                    # This occured in my plain vmlinux. Not sure what it's from, but removing
                    if "..." in line:
                        continue                    

                    # Count up operation types:

                    # Loads and stores are counted by KASAN instrumentation
                    if ("__asan_store" in line) or ("kasan_check_write" in line):
                        self.instr_count_map[funcname]["write"] += 1

                    if ("__asan_load" in line) or ("kasan_check_read" in line):                        
                        self.instr_count_map[funcname]["read"] += 1

                    # Calls and returns counted by opcodes
                    if " callq" in line:
                        # Calls to ASAN stuff don't count
                        if not (("__asan" in line) or ("kasan" in line)):
                            self.instr_count_map[funcname]["call"] += 1

                    if "retq" in line:
                        self.instr_count_map[funcname]["return"] += 1                        
                    
                    # Parse line into addr, bytes, opcode, regs
                    line_chunks = line.split("\t")
                    num_chunks = len(line_chunks)
                    if num_chunks == 2:
                        addr = line_chunks[0][:-1]
                        instr_bytes = line_chunks[1]
                        opcode = "nop"
                        regs = ""
                    elif num_chunks == 3:
                        addr = line_chunks[0][:-1]
                        instr_bytes = line_chunks[1]
                        args = line_chunks[2].split()
                        if len(args) > 1:
                            opcode = args[0]
                            regs = args[1]
                        else:
                            opcode = args[0]
                            regs = ""
                    else:
                        raise Exception("Could not parse line: " + line.strip())

                    num_bytes = len(instr_bytes.split())
                    self.instr_count_map[funcname]["size"] += num_bytes
                    self.instr_count_map[funcname]["total"] += 1
                    
                    # Calls to free routines are frees
                    if opcode == "callq":
                        self.instr_count_map[funcname]["call"] += 1
                        if "<kfree>" in line or "<kmem_cache_free>" in line or "<kvfree>" in line:
                            self.instr_count_map[funcname]["free"] += 1

                    # Build list of returns inside each function
                    if opcode == "retq" or "retq" in regs:
                        if not funcname in self.return_map:
                            self.return_map[funcname] = set()
                        self.return_map[funcname].add(addr)

                        
        # Optional: print out the extracted operation counts
        '''
        for f in self.instr_count_map:
            print("Function " + f + " had:")
            for op in ["read", "write", "call", "return", "free"]:
                print("\t" + str(self.instr_count_map[f][op]) + " " + op)
        '''

        # Lastly, if we had a plain vmlinux, take sizes from the plain instead.
        if self.has_plain_vmlinux:
            for f in self.instr_count_map_plain:
                if f in self.instr_count_map:
                    #print("Updating size of " + f + " from " + str(self.instr_count_map[f]["size"])
                    #      + " to " + str(self.instr_count_map_plain[f]["size"]))
                    self.instr_count_map[f]["size"] = self.instr_count_map_plain[f]["size"]
                    self.instr_count_map[f]["total"] = self.instr_count_map_plain[f]["total"]

    # Use addr2line to get info about the instructions in the vmlinux
    def batch_get_info(self, plain, follow_inline=False):

        dirs = []
        funcs = []
        files = []

        # self.addr_list is an unordered set, make a list
        addresses = []
        for a in self.addr_list:
            addresses.append(a)

        vmlinux = self.vmlinux
        if plain:
            vmlinux += "_plain"
            
        # Run batches of 10,000 instrs at a time.
        # These are command line arguments for addr2line, so there
        # are limits to how many can be processed at one time (fit in argv).
        batch_size = 20000
        num_batches = int(len(self.addr_list) / batch_size) + 1
        
        for i in range(0,num_batches):
            batch_start = i * batch_size
            batch_end = batch_start + batch_size
            addr2line_cmd = ['addr2line','-i', '-pfe', vmlinux]
            for x in addresses[batch_start:batch_end]:
                addr2line_cmd += [x]

            output = subprocess.check_output(addr2line_cmd).splitlines()
            
            # Iterate over output. Contains alternating root and inline lines
            # Fist char as space or not differentiates them. Use bottom-most inline
            # entry if any, else use root line.
            func = ""
            filename = ""
            for line in output:
                line_fields = line.split()
                if (line[0] != ' '):
                    if func != "" and filename != "":
                        funcs.append(func)
                        files.append(filename)
                    if len(line_fields) <= 2:
                        func = "?"
                        filename = "?"
                    else:
                        # If we don't have file information, create a fake file for this function
                        # Only a few cases for our vmlinux
                        if "?" in line_fields[2]:
                            func = line_fields[0] + ".v:" + line_fields[0]
                            filename = line_fields[0] + ".v"
                        else:
                            func = line_fields[2].split(":")[0] + ":" + line_fields[0]
                            filename = line_fields[2].split(":")[0]
                            if not plain:
                                # Create a map of line numbers where functions start.
                                # Used in the object explorer
                                funcname = "".join(self.re_kernel.findall(func))
                                line_no = line_fields[2].split(":")[1]
                                self.function_line_numbers[funcname] = line_no
                else:
                    # If we are following inlining, then first entry is correct.
                    # Otherwise, read to last entry.
                    if not follow_inline:
                        # Same as above, get full name of filepath for function
                        #func = line_fields[2]
                        func = line_fields[4].split(":")[0] + ":" + line_fields[2]
                        filename = line_fields[4].split(":")[0]
                    
            funcs.append(func)
            files.append(filename)

        for fh in files:
            dirs.append(os.path.dirname(fh))
        import itertools

        for i in range(0, len(funcs)):
            ip = addresses[i]
            funcname = "".join(self.re_kernel.findall(funcs[i]))
            filename = "".join(self.re_kernel.findall(files[i]))
            dirname = "".join(self.re_kernel.findall(dirs[i]))
            
            # uSCOPE does equality comparisons on filepaths and filenames as strings.
            # It's important that equal paths (e.g., "./dir" and "dir/" and "dir/blah/..")
            # have the same exact string representation. os.path.normpath() does this
            # out of the box :)
            funcname = os.path.normpath(funcname)
            filename = os.path.normpath(filename)
            dirname = os.path.normpath(dirname)
            topdirname = dirname.split("/")[0]

            # Build instr and function level semantic maps. Clustering always bottoms out
            # at one of these two things, so these are all we need.
            self.ip_to_func[ip] = funcname
            self.ip_to_file[ip] = filename
            self.ip_to_ip[ip] = ip
            self.ip_to_dir[ip] = dirname
            self.ip_to_topdir[ip] = topdirname
            self.ip_to_mono[ip] = "mono"
            self.func_to_func[funcname] = funcname
            self.func_to_file[funcname] = filename
            self.func_to_dir[funcname] = dirname
            self.func_to_topdir[funcname] = topdirname
            self.func_to_mono[funcname] = "mono"
            self.file_to_dir[filename] = dirname
            self.file_to_topdir[filename] = topdirname

    # If we load multiple CAPMAPs, set the size of an object to the average.
    def set_average_sizes(self):
        print("\tSetting object sizes from all capmaps...")
        
        # Set object sizes to average from map
        for objaddr in self.capmap_object_sizes:
            
            # Only print and update if not all the same. TODO compute in a better way
            list_same = True
            val = self.capmap_object_sizes[objaddr][0]
            for x in self.capmap_object_sizes[objaddr]:
                if x != val:
                    list_same = False
                    break
            if list_same == True:
                continue
            
            #print("For object " + objaddr + " we found these sizes:")
            avg = int(float(sum(self.capmap_object_sizes[objaddr])) / len(self.capmap_object_sizes[objaddr]))
            obj = self.get_object(objaddr)
            if obj != None:
                self.dg.node[obj]["size"] = avg
            else:
                print("Could not lookup obj: " + objaddr)
            #print(str(self.capmap_object_sizes[objaddr]))
            #print("Average: " + str(avg))
            #print("\n")

    # Add a single dg into an aggregate running dg of all loaded CAPMAPs.
    def add_capmap(self, dg, fn, found_compressed):

        number_calls = 0
        added_obj_nodes = 0
        added_instr_nodes = 0
        added_edges = {}
        for op in ops:
            added_edges[op] = 0

        size = int(os.path.getsize(fn) / (1024 * 1024))
        print("\tProcessing " + os.path.split(fn)[1] + " (" + str(size) + "MB)")

        if "PRIV" not in fn:
            show_debug = True
        else:
            show_debug = False

        #if size < 50 and not found_compressed:
        #    raise Exception("Tiny CAPMAP file. Error?")

        for node in dg:

            # If I don't have this node, add it and set attributes
            if not node in self.dg:
                self.dg.add_node(copy.deepcopy(node))
                for prop in ["size", "allocator", "va", "slab_cache", "name", "weight"]:
                    if prop in dg.node[node]:
                        self.dg.node[node][prop] = dg.node[node][prop]
                if node[0] == NodeType.OBJECT:
                    added_obj_nodes += 1
                else:
                    added_instr_nodes += 1

            # Loop over successors to get edges
            for objnode in dg.successors(node):

                # If didn't have other vertex, add as well
                if not objnode in self.dg:
                    self.dg.add_node(copy.deepcopy(objnode))
                    for prop in ["size", "allocator", "va", "slab_cache", "name", "weight"]:
                        if prop in dg.node[objnode]:
                            self.dg.node[objnode][prop] = dg.node[objnode][prop]

                    if objnode[0] == NodeType.OBJECT:
                        added_obj_nodes += 1
                    else:
                        added_instr_nodes += 1

                # Next, either add new edge or just add weights onto existing edge.
                edge_data = dg.get_edge_data(node, objnode)
                number_calls += edge_data["call"]
                if not self.dg.has_edge(node, objnode):
                    self.dg.add_edge(node, objnode,
                                     read = edge_data["read"],
                                     write = edge_data["write"],
                                     call = edge_data["call"],
                                     free = edge_data["free"])
                    self.dg.get_edge_data(node, objnode)["return"] = edge_data["return"]

                    for op in ops:
                        if edge_data[op] > 0:
                            added_edges[op] += 1
                else:
                    for op in ops:
                        self.dg.get_edge_data(node, objnode)[op] += edge_data[op]

        total_added = added_obj_nodes + added_instr_nodes
        if self.verbose:
            print("\t\tTotal calls: " + str(number_calls))
            print("\t\tAdded object nodes: " + str(added_obj_nodes))
            print("\t\tAdded instr nodes: " + str(added_instr_nodes))
            for op in ops:
                print("\t\tAdded " + op + " edges: " + str(added_edges[op]))
                total_added += added_edges[op]
            print("\t\tTotal added from " + os.path.split(fn)[1] + ": " + str(total_added))

    # If we have a .funcs file, use that to scale this CAPMAP by those counts
    def scale_capmap(self):

        # Skip if we built this from a directory
        if not self.from_single_file:
            print("\tSkipping scaling, this is building a combined CMAP")
            return

        # Look for .funcs file and add if we have it.
        cmap_file = self.kmap_file
        funcfile = os.path.basename(self.kmap_file).split(".")[0] + ".funcs"
        funcpath = os.path.join(os.path.dirname(self.kmap_file), funcfile)
        #print("Checking for funcs file " + funcpath)
        if os.path.exists(funcpath):
            print("\tFound funcfile! Scaling with " + funcpath)
        else:
            return

        # Read .func file and build dict of counts from it
        func_counts = {}
        fh = open(funcpath, "r")
        lines = fh.readlines()
        index = 0
        for l in lines:

            # Skip first two lines
            index += 1
            if index < 3:
                continue

            # Remove extra white space
            l = l.strip()
            l_next = l.replace("  ", " ")
            while l_next != l:
                l = l_next
                l_next = l.replace("  ", " ")

            # Split into fields and assign to vars
            parts = l.split(" ")
            fname = parts[0] 
            if "." in fname:
                fname = fname.split(".")[0]           
            fcount = int(parts[1])
            func_counts[fname] = fcount

        capmap_call_counts = {}
        total_capmap_calls = 0
        # Next, count up how many times each func was called
        # Note that ftrace only reports function names up to 30 characters,
        # so we only match on first 30 chars.
        for node in self.dg:
            if node[0] == NodeType.SUBJECT:
                for obj_node in self.dg.successors(node):
                    edge = self.dg.get_edge_data(node, obj_node)
                    if edge["call"] > 0:
                        called_func_long = self.ip_to_func[self.get_node_ip(obj_node)]
                        if ":" in called_func_long:
                            called_func_long = called_func_long.split(":")[1]
                            called_func = called_func_long[0:30]
                            if not called_func in capmap_call_counts:
                                capmap_call_counts[called_func] = 0
                            capmap_call_counts[called_func] += edge["call"]
                            total_capmap_calls += edge["call"]
                        else:
                            print("Failed to count for func: " + called_func)
                            continue

        # Make a list of all functions from both func file and capmap
        funcs_capmap = list(capmap_call_counts)
        funcs_funcfile = list(func_counts)
        all_funcs = list(set(funcs_capmap).union(set(funcs_funcfile)))

        # Print sorted list
        func_count_list = []
        func_count_dict = {}
        total_agree = 0
        total_disagree = 0
        total_ftrace = 0
        total_capmap = 0
        for f in all_funcs:
            if f in func_counts:
                ftrace_count = func_counts[f]
                total_ftrace += ftrace_count
            else:
                ftrace_count = 0

            if f in capmap_call_counts:
                capmap_count = capmap_call_counts[f]
                total_capmap += capmap_count
            else:
                capmap_count = 0

            if ftrace_count == 0 or capmap_count == 0:
                ratio = 0
            else:
                ratio = float(capmap_count) / ftrace_count

            total_agree += min(ftrace_count, capmap_count)
            total_disagree += abs(max(ftrace_count,capmap_count) - min(ftrace_count, capmap_count))

            func_count_dict[f] = ((ratio, ftrace_count, capmap_count))
            func_count_list.append((ratio, f, ftrace_count, capmap_count))

        if self.verbose:
            print("\t\tTotal agree: " + str(total_agree))
            print("\t\tTotal disagree: " + str(total_disagree))
            print("\t\tOverlap: " + str(round(float(total_agree) / (total_agree + total_disagree) * 100.0, 3)) + "%")
            print("\t\tTotal percent increase: " + str(round(float(total_capmap) / total_ftrace * 100.0 - 100.0, 3)))

        # Count up the op counts from each func and store for scaling logic.
        # This map uses just the func name without the file so it will match from the
        # count file.
        total_op_counts = {}
        for op in ops:
            total_op_counts[op] = 0
        func_op_counts = {}
        for node in self.dg:
            if node[0] == NodeType.SUBJECT:
                func = self.ip_to_func[self.get_node_ip(node)]
                if ":" in func:
                    func = func.split(":")[1]
                else:
                    print("Skipping " + func)
                    continue

                if not func in func_op_counts:
                    func_op_counts[func] = {}
                    for op in ops:
                        func_op_counts[func][op] = 0
                for obj_node in self.dg.successors(node):
                    edge = self.dg.get_edge_data(node, obj_node)
                    for op in ops:
                        if edge[op] > 0:
                            total_op_counts[op] += edge[op]
                            func_op_counts[func][op] += edge[op]

        # Now go through the CAPMAP again, this time scaling the edge weights.
        # TODO: for now, we are only scaling the case where the func appears
        # in both the CAPMAP and the func count file. Other edges not scaled.
        removed_ops = {}
        for op in ops:
            removed_ops[op] = 0
        for node in self.dg:
            if node[0] == NodeType.SUBJECT:
                func = self.ip_to_func[self.get_node_ip(node)]
                if ":" in func:
                    func = func.split(":")[1]
                else:
                    continue

                # Find scaling factor for this function
                if func in func_counts and func in capmap_call_counts:
                    ftrace_count = func_counts[func]
                    capmap_count = capmap_call_counts[func]
                    if ftrace_count == 0 or capmap_count == 0:
                        continue

                    scale_factor = float(ftrace_count) / capmap_count
                else:
                    continue

                for obj_node in self.dg.successors(node):
                    edge = self.dg.get_edge_data(node, obj_node)
                    for op in ops:
                        if edge[op] > 0:
                            current = edge[op]
                            new = max(int(current * scale_factor), 1)
                            removed = current - new
                            removed_ops[op] += removed
                            #print("\t" + op + " old count = " + str(current) + ", new=" + str(new) + ", removed=" + str(removed))
                            edge[op] = new

        if self.verbose:
            print("\tScaling results:")
            for op in ops:
                starting_count = total_op_counts[op]
                removed = removed_ops[op]
                percent_reduction = round(float(removed) / starting_count * 100.0, 2) if starting_count > 0 else 0.0
                print("\t\tFor op=" + op + " had " + str(starting_count) + ", then removed " + str(removed) + " for a reduction of " + str(percent_reduction) +"%")

    # This function takes the supplied CAPMAP digraph object and writes it into
    # a new .cmap.comp file. Only triggered if you load an uncompressed capmap.
    def make_compressed_capmap(self, dg, fn):

        cfile = open(fn + ".comp", "w")
        cfile.write("# This is a compressed .cmap file: all object instances are merged together.\n")
        cfile.write("# Additional metadata about objects and call edges are inlined with comments for human readers.\n")
        
        # First dump CFG to the top of the new file. Sort by IP for easier human reading later.
        output_lines = []
        for node in dg:
            if node[0] == NodeType.SUBJECT:
                for dest in dg.successors(node):
                    if dest[0] == NodeType.OBJECT:
                        continue
                    edge = dg.get_edge_data(node, dest)
                    if edge["call"] > 0:
                        srcip = node[1]
                        destip = dest[1]
                        comment_line = "# "
                        if srcip in self.ip_to_func and destip in self.ip_to_func:
                            comment_line += self.ip_to_func[srcip] + " -> " + self.ip_to_func[destip]
                        comment_line += "\n"
                        data_line = srcip + " " + destip + " " + str(edge["call"]) + "\n"
                        output_lines.append((data_line, comment_line))
        for (data,comment) in sorted(output_lines):
            cfile.write(comment)
            cfile.write(data)
                        
        # Next, dump in objs and accesses. Sort by IP for easier human reading later.
        for node in dg:
            if node[0] == NodeType.OBJECT:

                # Write out line for this object. alloc_time, free_time, and free_ip are gone
                objip = node[2]
                size = dg.node[node]["size"]
                allocator = dg.node[node]["allocator"]
                va = dg.node[node]["va"]
                slab_cache = dg.node[node]["slab_cache"]

                cfile.write("# " + dg.node[node]["name"] +"\n")
                # For heap objects the object_addr is alloc_ip (first field), for globals / special the object_addr is va
                if node[1] == MemType.HEAP or allocator == "VMALLOC" or "STACK" in allocator:
                    cfile.write(objip + ",0," + va + "," + str(size) + ",0,0,(null)," + allocator + ",(null)," + slab_cache + "\n")
                elif node[1] == MemType.SPECIAL:
                    cfile.write(objip +",0," + va +"," + str(size) + ",0,0,(null)," + allocator + ",(null)," + slab_cache + "\n")
                else:
                    cfile.write("(null),0," + va +"," + str(size) + ",0,0,(null)," + allocator + ",(null)," + slab_cache + "\n")

                # Then write out all accessors, if any
                output_lines = []
                for accessor in dg.predecessors(node):
                    # It's instr_ip, writes, reads, time?
                    edge_data = dg.get_edge_data(accessor, node)
                    reads = edge_data["read"]
                    writes = edge_data["write"]
                    frees = edge_data["free"]
                    output_lines.append("  " + accessor[1] + "," + str(writes) + "," + str(reads) + "," + str(frees) + "\n")
                for l in sorted(output_lines):
                    cfile.write(l)

    # Create some special CAPMAPs from this run.
    # We create:
    # 1) A PRIV CAPMAP, which is all weights set to 1
    # 2) If we were given a single capmap, create a scaled to 1 billion calls version
    # 3) If there were multiple input CAPMAPS, make a weighted capmap of all edges
    def create_special_capmaps(self, name):
        
        print("\tCreating special CAPMAPs in " + name)

        # First CAPMAP we make: all weights set to 1
        new_cmap = self.dg.to_directed()
        for node in new_cmap:
            for objnode in new_cmap.successors(node):
                edge = new_cmap.get_edge_data(node, objnode)
                for op in ops:
                    if edge[op] > 0:
                        edge[op] = 1
        self.make_compressed_capmap(new_cmap, name + "/" + "PRIV.cmap")
        print("\tMade privilege CAPMAP: " + name + "/" + "PRIV.cmap")

        # Next CAPMAP we might make: fully weighted if from multiple
        if not self.from_single_file:
            new_cmap = self.dg.to_directed()
            self.make_compressed_capmap(new_cmap, name + "/" + "PERF.cmap")
            print("\tMade combined weight CAPMAP: " + name + "/" + "PERF.cmap")

        # Next CAPMAP we make: Scaled to 1 billion calls
        new_cmap = self.dg.to_directed()
        # First calculate total dynamic calls
        total_calls = 0
        for node in new_cmap:
            for objnode in new_cmap.successors(node):
                edge = new_cmap.get_edge_data(node, objnode)
                total_calls += edge["call"]
        print("\tHad " + str(total_calls) + " total calls.")
        scaling_factor = round(1000000000.0 / float(total_calls), 6)
        print("Scaling factor = " + str(scaling_factor))
        for node in new_cmap:
            for objnode in new_cmap.successors(node):
                edge = new_cmap.get_edge_data(node, objnode)
                for op in ops:
                    if edge[op] > 0:
                        new_amt = max(int(float(edge[op]) * scaling_factor),1)
                        #print("Changed calls from " + str(edge["call"]) + " to " + str(new_calls))
                        edge[op] = new_amt
        self.make_compressed_capmap(new_cmap, name + "/" + "scaled.cmap")
        print("\tMade privilege CAPMAP: " + name + "/" + "scaled.cmap")
            
    # Traverse a capmap, and add any unknown instructions into the various maps.
    # Instructions will only have unknown IPs if they were written to
    # post-compilation and thus were missed by objdump. 
    def fix_misaligned_instructions(self, cmap):
        fixed_misaligned_nodes = 0
        for node in cmap:
            if node[0] != NodeType.SUBJECT:
                continue
            ip = node[1]
            # Fix misaligned instructions
            if not ip in self.ip_to_func:
                #print("Warning: misaligned instruction. Fixing " + self.get_node_ip(node))
                fixed = False
                for i in range(-48,48):
                    prev_ip = hex(int(ip, 16) + i)[2:-1]
                    if prev_ip in self.ip_to_func:
                        fixed = True
                        fixed_misaligned_nodes += 1                        
                        my_func = self.ip_to_func[prev_ip]
                        my_file = self.ip_to_file[prev_ip]
                        my_dir = self.ip_to_dir[prev_ip]
                        my_topdir = self.ip_to_topdir[prev_ip]
                        #print("Found, bound " + ip + " to " + my_func)
                        self.ip_to_ip[ip] = ip
                        self.ip_to_func[ip] = my_func
                        self.ip_to_file[ip] = my_file
                        self.ip_to_dir[ip] = my_dir
                        self.ip_to_topdir[ip] = my_topdir
                        break
                if not fixed:
                    raise Exception("Could not fix misaligned instr: " + ip)
        if fixed_misaligned_nodes > 0:
            print("\tFixed " + str(fixed_misaligned_nodes) + " misaligned instructions (a small number are expected from dynamic code writing.)")
        if fixed_misaligned_nodes > 100:
            raise Exception("More than 100 instructions were misaligned. Likely wrong vmlinux for .cmap file.")
        
    # After loading in a raw CAPMAP produced by Memorizer, there are code and objects
    # that are debugging / invalid and should be removed before analysis.
    # Invalid objects include NONE, BUG, etc, so we remove those and their edges.
    # We also remove edges from nodes that are not in the plain version of Memorizer,
    # which trims away KASAN and Memorizer code/data.
    # Note that this function removes elements from a provided capmap_dg, not just self.dg
    def remove_invalid_CAPMAP_entries(self, capmap_dg, filename):

        # First remove bad objects
        invalid_objs = ["BUG", "INDUCED_ALLOC", "MEMORIZER", "NONE", "USER"]
        #print("Removing invalid objects.")
        for node in list(capmap_dg):
            if node[0] == NodeType.OBJECT:
                if self.get_node_memtype(node) == MemType.SPECIAL:
                    if self.get_node_ip(node) in invalid_objs:
                        for obj_node in list(capmap_dg.predecessors(node)):
                            capmap_dg.remove_edge(obj_node, node)
                        capmap_dg.remove_node(node)

        # Then remove code + corresponding objects not in plain if we have a plain
        if self.has_plain_vmlinux:
            #print("Removing code not in plain.")
            functions_to_remove = set()
            for f in self.instr_count_map:
                if not f in self.instr_count_map_plain:
                    functions_to_remove.add(f)
                    
                # Remove functions that had no debugging info; it's a small amount. TODO cleanup.
                if f == ".":
                    functions_to_remove.add(f)

            # Walk the graph and collect all nodes that belong to functions we are removing
            nodes_to_remove = set()
            for node in capmap_dg:
                if node[0] == NodeType.SUBJECT:
                    ip = self.get_node_ip(node)
                    func = self.ip_to_func[ip]
                    if func in functions_to_remove:
                        nodes_to_remove.add(node)

            # The remove those nodes and connected edges
            for node in nodes_to_remove:
                capmap_dg.remove_node(node)

            # Okay, these are now removed from the CAPMAP graph itself. Lastly, remove from the functions list
            removed_funcs = 0
            for f in functions_to_remove:
                if f in self.functions:
                    removed_funcs += 1
                    self.functions.remove(f)

            if removed_funcs > 0:
                print("\tSuccesfully removed " + str(removed_funcs) + " functions not in plain.")

        else:
            print("\tSkipping removing code not in plain, we didn't have a plain.")

    # This function takes a list of alloc times, free times, and object sizes
    # and computes aggregate average live or max live statistics based on that
    # data
    def compute_dynamic_obj_size(self, event_list, object_addr):

        # Add all events to a hash table. At the alloc time, we log
        # in a positive size count. At the free time, we log in a negative.
        # All that is left is running through sorted timestamps
        events = {}
        max_instance_size = 0
        for (alloc_time, free_time, size) in event_list:
            #print(str(alloc_time) + " , " + str(free_time) + " , " + str(size))
            if not alloc_time in events:
                events[alloc_time] = 0
            events[alloc_time] += size
            if not free_time in events:
                events[free_time] = 0
            events[free_time] -= size
            if size > max_instance_size:
                max_instance_size = size

        # We now process the event list, computing max and average
        current_size = 0
        max_size = 0
        current_num_instances = 0
        max_num_instances = 0
        weighted_sum = 0
        timesteps_added = 0
        last_timestep = 0

        for e in sorted(list(events)):
            current_size += events[e]

            # Track number instances
            if events[e] > 0:
                current_num_instances += 1
            if events[e] < 0:
                current_num_instances -= 1
            if current_num_instances > max_num_instances:
                max_num_instances = current_num_instances

            #print("time=" + str(e) + ", size=" + str(current_size))
            if current_size > max_size:
                max_size = current_size
            if last_timestep == 0:
                last_timestep = e
            else:
                duration = e - last_timestep
                # Only average over periods where we have at least 1 obj
                if current_size > 0:
                    weighted_sum += duration * current_size
                    timesteps_added += duration
                last_timestep = e

        if current_size != 0:
            raise Exception("Error in max size calculation.")

        if timesteps_added > 0:
            average_size = round(float(weighted_sum) / timesteps_added,1)
        else:
            average_size = max_instance_size

        if max_size > 1000000:
            print("WARN: got a large max_live from " + str(object_addr) + ":" + str(max_size))
            print("Max instance size: " + str(max_instance_size))
            print("Max live size: " + str(max_size))
            print("Average live size: " + str(average_size))

        print("For obj " + str(object_addr) + " max_instance=" + str(max_instance_size) + " max_live=" + str(max_size) + " avg_size=" + str(average_size))
        return int(average_size)

    # This function computes a set called live_functions.
    # A function is live if it has call or return edges. This set it used for:  
    # 1) to be able to calculate PS effects of removing dead code,
    # 2) As an optimization for the code clusterer to save compute time
    def calc_live_functions(self):
        for node in self.dg:
            if node[0] == NodeType.SUBJECT:
                src_ip = self.get_node_ip(node)
                src_func = self.ip_to_func[src_ip]                
                for obj_node in self.dg.successors(node):
                    if obj_node[0] == NodeType.SUBJECT:
                        # This is a call/return edge
                        dest_ip = self.get_node_ip(obj_node)
                        dest_func = self.ip_to_func[dest_ip]
                        self.live_functions.add(src_func)
                        self.live_functions.add(dest_func)
                    else:
                        self.live_functions.add(src_func)
        if self.verbose:
            print("\tTotal functions: " + str(len(self.functions)))
            print("\tLive functions: " + str(len(self.live_functions)))    
                        
    # Create object ownership maps for all objects.
    # For heap objects, this is determined from the code location of the allocating instruction.
    # For global objects, we use the symbol_table and global_table for the associations.
    #
    # It's possible that files we didn't find code from will occur here.
    # For example, this could be caused by a .h that defines a global but no code.
    # TOD Currently skipping this case, could try adding to maps.
    # (handle case where this_file not in self.file_to_dir)
    def build_object_ownership_maps(self):

        # Create the object ownership maps. Different logic for heap / global objects.
        for node in self.dg:
            if node[0] == NodeType.OBJECT:
                this_ip = self.get_node_ip(node)
                
                # The 'no ownership' case: make reflexive map
                self.obj_no_cluster[this_ip] = this_ip
                
                # Heap objects: just use instruction                
                if self.get_node_memtype(node) == MemType.HEAP:
                    self.obj_owner_func[this_ip] = self.ip_to_func[this_ip]
                    self.obj_owner_file[this_ip] = self.ip_to_file[this_ip]
                    self.obj_owner_dir[this_ip] = self.ip_to_dir[this_ip]
                    self.obj_owner_topdir[this_ip] = self.ip_to_topdir[this_ip]
                    
                # Global objects: use symbol_table and global_table in that order
                if self.get_node_memtype(node) == MemType.GLOBAL:
                    this_file = None
                    if this_ip in self.symbol_table_src_files:
                        this_file = self.symbol_table_src_files[this_ip]
                    elif this_ip in self.global_table_src_files:
                        this_file = self.global_table_src_files[this_ip]
                    if this_file != None and this_file in self.file_to_dir:
                        this_dir = self.file_to_dir[this_file]
                        this_topdir = self.file_to_topdir[this_file]
                        #print("Mapped global " + this_ip + " (" + self.dg.node[node]["name"] + ")"
                        #      + " to file " + this_file + " in dir " + this_dir + " in topdir " +
                        #      this_topdir)
                        self.obj_owner_file[this_ip] = this_file
                        self.obj_owner_dir[this_ip] = this_dir
                        self.obj_owner_topdir[this_ip] = this_topdir

        # Another thing we'll compute here is the file_to_funcs map.
        # Unlike the other maps, each of these is a *set*
        for func in self.functions:
            this_file = self.func_to_file[func]
            if not this_file in self.file_to_funcs:
                self.file_to_funcs[this_file] = set()
            self.file_to_funcs[this_file].add(func)                        

                        
    # Some external code (edge assignment, etc) requires that the operation
    # type counts match the number of edges. Due to dynamic code writing,
    # occasionally we statically miss operation counts. Check and fix here.
    def sanity_check_op_counts(self):

        # First, compute the number of dynamic op counts we have in trace

        # Set all counts to 0
        op_counts = {}
        for f in self.functions:
            op_counts[f] = {}
            for op in ops:
                op_counts[f][op] = set()

        # Traverse all edges, keep track of op instructions for each func
        for node in self.dg:

            # Skip objects, compute the func we're in
            if node[0] == NodeType.OBJECT:
                continue
            
            ip = self.get_node_ip(node)
            func = self.ip_to_func[ip]
            
            for obj_node in self.dg.successors(node):
                edge = self.dg.get_edge_data(node, obj_node)
                for op in ops:
                    if edge[op] > 0:
                        op_counts[func][op].add(ip)

        # Then, use that count to compare to static classification.
        # There are some very rare discrepancies, fix here. I believe they
        # come from dynamic code writes?
        for f in self.functions:
            for op in ops:
                if len(op_counts[f][op]) > self.instr_count_map[f][op]:
                    #print(op + " count disagreement on " + f)
                    #print("\tDynamic: " + str(len(op_counts[f][op])))
                    #print("\tStatic: " + str(self.instr_count_map[f][op]))
                    self.instr_count_map[f][op] = len(op_counts[f][op])
            
    # Our infrastructure currently only captures forward (call) edges due to limitations
    # in ftrace. 
    # By assuming each call returns to its caller, we can generate appropriate backwards edges.
    # This function implements that logic.
    # Distributes the return weights evenly over the retq instructions back from the caller.
    def add_returns(self, dg):

        # Make copy of keys with list() so can add while iterating
        for node in list(dg):
            if node[0] == NodeType.SUBJECT:
                for obj_node in list(dg.successors(node)):
                    edge = dg.get_edge_data(node, obj_node)
                    if edge["call"] > 0:

                        call_instr = self.get_node_ip(node)
                        num_calls = edge["call"]

                        called_instr = self.get_node_ip(obj_node)
                        called_function = self.ip_to_func[called_instr]

                        # Some functions don't return. That's actually okay.
                        if not called_function in self.return_map:
                            continue

                        rets_in_called = self.return_map[called_function]
                        num_rets = len(rets_in_called)

                        # Check if dest instr is in CAPMAP, if not then add
                        dst_node  = (NodeType.SUBJECT, call_instr)
                        if not dg.has_node(dst_node):
                            dg.add_node(dst_node, size=INSTR_SIZE)

                        ret_counts = divide_evenly(num_calls, num_rets)

                        # Add edge back from each return
                        for ret_instr, ret_count in zip(rets_in_called, ret_counts):

                            # Not adding edges for the 0 weights. Not sure if need to skip
                            if ret_count == 0:
                                continue

                            # Check if source instr is in CAPMAP, if not then add
                            src_node  = (NodeType.SUBJECT, ret_instr)
                            if not dg.has_node(src_node):
                                dg.add_node(src_node, size=INSTR_SIZE)

                            # Add return edge
                            if not dg.has_edge(src_node, dst_node):
                                dg.add_edge(src_node, dst_node, write = 0, read = 0,
                                                 call = 0,free = 0)
                                dg.get_edge_data(src_node, dst_node)["return"] = ret_count
                                self.number_returns += 1

    # Some reporting. TODO clean up.
    def report_stats(self):

        total_instr_size = 0
        total_global_size = 0
        total_heap_size = 0
        total_vmem_size = 0
        total_memblock_size = 0
        total_anon_size = 0
        total_stack_size = 0
        total_special_size = 0
        total_vmalloc_size = 0

        # Get code size
        for f in self.functions:
            total_instr_size += self.instr_count_map[f]["size"]

        # Get object size
        for node in self.dg:
            if node[0] == NodeType.OBJECT:

                size = self.get_node_size(node)
                allocator = self.dg.node[node]["allocator"]

                # Heap and vmalloc mem
                if self.get_node_memtype(node) == MemType.HEAP:
                    total_heap_size += size
                elif allocator == "VMALLOC":
                    total_vmalloc_size += size

                # Globals
                elif self.get_node_memtype(node) == MemType.GLOBAL:
                    total_global_size += size

                # Handle the special cases:
                elif self.get_node_memtype(node) == MemType.SPECIAL:
                    node_ip = self.get_node_ip(node)
                    if node_ip == "VMEMMAP":
                        total_vmem_size += size
                    elif node_ip == "MEMBLOCK":
                        total_memblock_size += size
                    elif "ANON" in node_ip:
                        total_anon_size += size
                    elif node_ip in ["STACK_PAGE", "THREAD_STACK", "PER_CPU_STACK"]:
                        total_stack_size += size
                    elif node_ip == "GEN_HEAP" or node_ip[0:10] == "prealloced":
                        total_heap_size += size
                    #else:
                    #    print("Not sure what to do with: " + node_ip)

        total_data_size = total_instr_size + total_global_size + \
                          total_heap_size + total_vmem_size + \
                          total_memblock_size + total_anon_size + \
                          total_stack_size + total_vmalloc_size

        if self.verbose:
            print("SIZE ANALYSIS:")        
            print("\tInstr size: " + str(total_instr_size) + " (" + str(round(float(total_instr_size) / total_data_size * 100.0,2)) + "%)")
            print("\tGlobal size: " + str(total_global_size) + " (" + str(round(float(total_global_size) / total_data_size * 100.0,2)) + "%)")
            print("\tHeap size: " + str(total_heap_size) + " (" + str(round(float(total_heap_size) / total_data_size * 100.0,2)) + "%)")
            print("\tVmalloc size: " + str(total_vmalloc_size) + " (" + str(round(float(total_vmalloc_size) / total_data_size * 100.0,2)) + "%)")
            print("\tStack size: " + str(total_stack_size) + " (" + str(round(float(total_stack_size) / total_data_size * 100.0,2)) + "%)")
            print("\tMemblock size: " + str(total_memblock_size) + " (" + str(round(float(total_memblock_size) / total_data_size * 100.0,2)) + "%)")
            print("\tVMEM size: " + str(total_vmem_size) + " (" + str(round(float(total_vmem_size) / total_data_size * 100.0,2)) + "%)")
            print("\tANON size: " + str(total_anon_size) + " (" + str(round(float(total_anon_size) / total_data_size * 100.0,2)) + "%)")

        if self.verbose:
            print("Number of nodes in CAPMAP graph: " + str(len(self.dg)))
            print("Number of call edges: " + str(self.number_calls))
            print("Number of return edges: " + str(self.number_returns))
            print("Number of functions in instrumented vmlinux: " + str(len(self.instr_count_map)))
            print("Number of functions in plain vmlinux: " + str(len(self.instr_count_map_plain)))

            # Compute the average size of compartments for each kind of syntatic cut
            # This number is used a few places in the paper.
            cases = [
                ("TopDir", self.func_to_topdir),
                ("Dir", self.func_to_dir),
                ("File", self.func_to_file)]

            total_size = 0
            for f in self.functions:
                total_size += self.instr_count_map[f]["size"]

            for (name, cut) in cases:
                subjs = self.get_subjects(cut)
                num_subjs = len(subjs)
                avg = round(float(total_size) / num_subjs,2)
                #print("The average size for " + name + " is " + str(avg))

            most_instr = 0
            highest_obj = None

            for node in self.dg:
                if node[0] == NodeType.SUBJECT:
                    continue
                num_edges = len(list(self.dg.predecessors(node)))
                if num_edges > most_instr:
                    most_instr = num_edges
                    highest_obj = node
                #if self.get_node_ip(node) in ["STACK_PAGE", "THREAD_STACK", "PER_CPU_STACK"]:
                #    print("Found the stack! Degree: " + str(num_edges))
            print("The highest degree object was " + str(self.get_node_ip(highest_obj)) + " with degree " + str(most_instr))

        # If we have baseline cycles, print out cycles per call
        if self.baseline_cycles != None:
            total_calls = 0
            for node in self.dg:
                if node[0] == NodeType.SUBJECT:
                    for obj_node in self.dg.successors(node):
                        edge = self.dg.get_edge_data(node, obj_node)
                        if edge["call"] > 0:
                            total_calls += edge["call"]

    # This function makes a linkmap, which assigns a type (mediated/unmediated) to all non-empty
    # edges in the CAPMAP.
    # That is, linkmap[subj][obj][op] = mediated/unmediated
    # The subj_clusters cut defines the granularity of subjects. On the object side, obj_clusters
    # defines obj clustering for data objects. An edge is also added for each code object, which
    # also uses the granularity given by subj_clusters. By default, self-edges to code are
    # are unmediated, other subjects are mediated.
    def make_linkmap(self, subj_clusters, obj_clusters, default="mediated", special=""):

        linkmap = {}

        # Basic logic for a standard linkmap:
        for node in self.dg:

            if node[0] == NodeType.SUBJECT:
                subj_ip = self.get_node_ip(node)
                subj_cluster = subj_clusters[self.ip_to_func[subj_ip]]

                if not subj_cluster in linkmap:
                    linkmap[subj_cluster] = {}

                # obj_node can be data object or code for call/ret
                for obj_node in self.dg.successors(node):

                    obj_ip = self.get_node_ip(obj_node)
                    edge = self.dg.get_edge_data(node, obj_node)

                    # If subject, we use the subj clustering cuts to name this object in the linkmap
                    if obj_node[0] == NodeType.SUBJECT:

                        obj_cluster = subj_clusters[self.ip_to_func[obj_ip]]

                        # Add all types of edges, set to empty
                        if not obj_cluster in linkmap[subj_cluster]:
                            linkmap[subj_cluster][obj_cluster] = {}
                            for op in ops:
                                linkmap[subj_cluster][obj_cluster][op] = ""

                        # Default linkmaps will let call/ret within the compart be unmediated, others mediated
                        if subj_cluster == obj_cluster:
                            if edge["call"] > 0:
                                linkmap[subj_cluster][obj_cluster]["call"] = "unmediated"
                            if edge["return"] > 0:
                                linkmap[subj_cluster][obj_cluster]["return"] = "unmediated"
                        else:
                            if edge["call"] > 0:
                                linkmap[subj_cluster][obj_cluster]["call"] = default
                            if edge["return"] > 0:
                                linkmap[subj_cluster][obj_cluster]["return"] = default
                            
                    else:

                        # If object, we use the obj clustering cut to name this cluster
                        obj_cluster = obj_clusters[obj_ip]
                        if not obj_cluster in linkmap[subj_cluster]:
                            linkmap[subj_cluster][obj_cluster] = {}
                            for op in ops:
                                linkmap[subj_cluster][obj_cluster][op] = ""

                        if edge["read"] > 0:
                            linkmap[subj_cluster][obj_cluster]["read"] = default
                        if edge["write"] > 0:
                            linkmap[subj_cluster][obj_cluster]["write"] = default
                        if edge["free"] > 0:
                            linkmap[subj_cluster][obj_cluster]["free"] = default


        # There are two special kinds of linkmaps we can make: one-unmediated, and alloc-owner.

        # In both cases, we allow some "free" objects to fairly represent those positions:        
        object_exceptions = ["THREAD_STACK", "VMEMMAP", "MEMBLOCK"]
        object_exception_counts = 0
        if special in ["one-unmediated", "allocator-owner"]:
            for s in linkmap:
                for o in linkmap[s]:
                    if o in object_exceptions:
                        for op in linkmap[s][o]:
                            if linkmap[s][o][op] == "mediated":
                                linkmap[s][o][op] = "unmediated"
                                #print("Made unmediated: " + s + " " + o + " " + op)
                                object_exception_counts += 1
            print("Total object exception unmediations added: " + str(object_exception_counts))
                                
        # The one-unmediated case means each object gets one-unmediated edge to a subject.
        # It also means that each self-call edge is unmediated, which we inherit from above.
        if special == "one-unmediated":
            
            print("Constructing a special one-unmediated linkmap!")

            # Traverse the CAPMAP, count up total dynamic weights coming into each object
            object_weights = {}
            for node in self.dg:
                if node[0] == NodeType.OBJECT:
                    continue
                src_ip = self.get_node_ip(node)
                src_func = self.ip_to_func[src_ip]
                src_cluster = subj_clusters[src_func]

                for obj_node in self.dg.successors(node):
                    if obj_node[0] == NodeType.SUBJECT:
                        continue
                    edge = self.dg.get_edge_data(node, obj_node)
                    obj_ip = self.get_node_ip(obj_node)
                    obj_cluster = obj_clusters[obj_ip]

                    if not obj_cluster in object_weights:
                        object_weights[obj_cluster] = {}
                    if not src_cluster in object_weights[obj_cluster]:
                        object_weights[obj_cluster][src_cluster] = 0
                    object_weights[obj_cluster][src_cluster] += edge["read"] + edge["write"] + edge["free"]

            for o in object_weights:
                max_subj = None
                max_subj_weight = 0
                for s in object_weights[o]:
                    if object_weights[o][s] > max_subj or max_subj == None:
                        max_subj = s
                        max_subj_weight = object_weights[o][s]
                if max_subj != None:
                    if o in self.object_names:
                        name = self.object_names[o]
                    else:
                        name = o
                    #print("For object " + name + " the highest accessing subj is " + max_subj)

                    for op in ["read", "write", "free"]:
                        if op in linkmap[max_subj][o]:
                            if linkmap[max_subj][o][op] == "mediated":
                                #print("Set link " + s + " " + o + " " + op + " to unmediated.")
                                linkmap[max_subj][o][op] = "unmediated"
                                
        # The allocator-owner case means each object gets one-unmediated edge to its allocating subject.
        # It also means that each self-call edge is unmediated, which we inherit from above.
        if special == "allocator-owner":
            
            print("Constructing a special allocator-owner linkmap! Make sure you use obj_no_clusters; can't mix this with obj clustering.")

            # Step 1: loop over all objects, compute the subject owner.
            # Depends on heap/globals/etc
            object_owner = {}
            for node in self.dg:
                if node[0] == NodeType.SUBJECT:
                    continue
                
                obj_ip = self.get_node_ip(node)
                my_memtype = self.get_node_memtype(node)
                
                if my_memtype == MemType.HEAP:
                    if obj_ip in self.ip_to_func:
                        alloc_func = self.ip_to_func[obj_ip]
                        alloc_subj = subj_clusters[alloc_func]
                        object_owner[obj_ip] = set()
                        object_owner[obj_ip].add(alloc_subj)
                elif my_memtype == MemType.GLOBAL:
                    if obj_ip in self.obj_owner_file:
                        owning_file = self.obj_owner_file[obj_ip]
                        if owning_file in self.file_to_funcs:
                            accessing_funcs = self.file_to_funcs[owning_file]
                            object_owner[obj_ip] = set()
                            for func in accessing_funcs:
                                subj = subj_clusters[func]
                                object_owner[obj_ip].add(subj)
                        else:
                            print("Not sure which funcs: " + obj_ip + " " + owning_file)
                        
            # Step 2: Update the linkmap with allocator owner
            for s in linkmap:
                for o in linkmap[s]:
                    if o in object_owner:
                        this_owner_list = object_owner[o]
                        if s in this_owner_list:
                            obj = self.get_object(o)
                            name = self.dg.node[obj]["name"]
                            #print("I own this! " + o + " " + name + " owned by " + s)
                            for op in linkmap[s][o]:
                                if linkmap[s][o][op] == "mediated":
                                    linkmap[s][o][op] = "unmediated"
                                    #print("Allocator-owner made unmediated: " + s + " " + o + " " + op)

        '''
        print("Here is the linkmap!")
        for s in linkmap:
            print("Subject=" + s)
            for o in linkmap[s]:
                print("\tObject=" + o)
                for op in ops:
                    if linkmap[s][o][op] != "":
                        print("\t\t" + op + "=" + linkmap[s][o][op])
        '''
        return linkmap

    # Returns a set of all the subject clusters given a clustering map
    def get_subjects(self, subj_clusters):
        subjects = set()
        for f in subj_clusters:
            subj_cluster = subj_clusters[f]
            subjects.add(subj_cluster)
        return subjects

    # Returns a set of all the object clusters given a clustering map
    def get_objects(self, obj_clusters):
        objects = set()
        for o in obj_clusters:
            node_cluster = obj_clusters[node_ip]
            objects.add(node_cluster)
        return objects

    # Get an graph object from its objaddr/ip
    # Slow, could make map for O(1) lookups
    def get_object(self, objaddr):
        for o in self.dg:
            if o[0] == NodeType.OBJECT:
                if self.get_node_ip(o) == objaddr:
                    return o
        return None

    # Get the size of a node. It's either an instruction or a data object
    def get_node_size(self,node):
        return self.dg.node[node]["size"]

    # Get the instr type of a node. Returns None for objs.
    def get_instr_type(self, node):
        if node[0] == NodeType.SUBJECT:
            return node[1]
        else:
            return None

    # Return NodeType.SUBJECT or NodeType.OBJECT
    def get_node_type(self, node):
        return node[0]
    
    # Get the instruction related to a node (alloc_ip or access_ip)
    def get_node_ip(self, node):
        if node[0] == NodeType.OBJECT:
            return node[2] # alloc_ip for heap or va global
        if node[0] == NodeType.SUBJECT:
            return node[1] # instr_ip
        
    # Get the type of allocation (MemType.HEAP, MemType.GLOBAL, MemType.SPECIAL)
    def get_node_memtype(self, node):
        if node[0] != NodeType.OBJECT:
            raise Exception("Tried to get memtype of a non-object")
        return node[1]

# A utility function used for dividing a weight count onto edges.
# Divides an integer n into c buckets as evenly as possible.
# Minimum count is 1.
# Returns a list.
# E.g., divide_evenly(5,3) = [2, 2, 1]
def divide_evenly(n,c):
    int_part = max(n / c,1)
    buckets = [int_part] * c
    remainder = n - int_part * c
    for i in range(0, remainder):
        buckets[i] += 1
    return buckets

if __name__ == '__main__':
    if len(sys.argv) > 2:
        cmap = CAPMAP(sys.argv[1], sys.argv[2], verbose=True)
    else:
        print("python CAPMAP.py <vmlinux> <kmap>")
