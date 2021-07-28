#!/usr/bin/python

# This file contains the cost models for the various performance profiles,
# as well as the calculation scripts for computing overhead numbers.
# Given a CAPMAP, a compartmentalization, a hardware cost model, and a baseline cycle count,
# it computes overhead following the models in 5.3.2 of the uSCOPE paper.
#
# While this script is primarily used by other scripts, it can be run standalone
# using "python calculate_overhead.py <vmlinux> <kmap>" to test run on the syntactic cuts.

from CAPMAP import *
import sys

memops = ["read", "write", "free"]
ops = memops + ["call", "return"]

### Define the characteristics of our potential protection mechanisms ###
mechanisms = []

# Page table process / kernel context switch
mechanism_kernel = {}
mechanism_kernel["name"] = "Kernel context switch"
mechanism_kernel["tablename"] = "Kernel context switch"
mechanism_kernel["shortname"] = "kernelswitch"
mechanism_kernel["Tunmed"] = {}
mechanism_kernel["Tunmed"]["read"] = 0
mechanism_kernel["Tunmed"]["write"] = 0
mechanism_kernel["Tunmed"]["call"] = 0
mechanism_kernel["Tunmed"]["return"] = 0
mechanism_kernel["Tunmed"]["free"] = 0
mechanism_kernel["Tmed"] = {}
mechanism_kernel["Tmed"]["read"] = 6000
mechanism_kernel["Tmed"]["write"] = 6000
mechanism_kernel["Tmed"]["call"] = 6000
mechanism_kernel["Tmed"]["return"] = 6000
mechanism_kernel["Tmed"]["free"] = 6000
mechanism_kernel["Tunmed_ext_call"] = 6000
mechanism_kernel["objmax"] = True
mechanisms.append(mechanism_kernel)

# Page table + EPT
vmfunc_cost = 445 # used to be 200, calibrate up to 445
capmap_cost = 200
trap_cost = 200
mechanism_PT = {}
mechanism_PT["name"] = "Page Table + EPT"
mechanism_PT["tablename"] = "PT + EPT"
mechanism_PT["shortname"] = "pagetable_ept"
mechanism_PT["Tunmed"] = {}
mechanism_PT["Tunmed"]["read"] = 0
mechanism_PT["Tunmed"]["write"] = 0
mechanism_PT["Tunmed"]["call"] = 0
mechanism_PT["Tunmed"]["return"] = 0
mechanism_PT["Tunmed"]["free"] = 0
mechanism_PT["Tmed"] = {}
mechanism_PT["Tmed"]["read"] = 2 * trap_cost + 2* vmfunc_cost + capmap_cost
mechanism_PT["Tmed"]["write"] = 2 * trap_cost + 2* vmfunc_cost + capmap_cost
mechanism_PT["Tmed"]["call"] = vmfunc_cost + capmap_cost
mechanism_PT["Tmed"]["return"] = vmfunc_cost + capmap_cost
mechanism_PT["Tmed"]["free"] = 2 * trap_cost + 2* vmfunc_cost + capmap_cost
mechanism_PT["Tunmed_ext_call"] = vmfunc_cost
mechanism_PT["objmax"] = True
mechanisms.append(mechanism_PT)

# SFI
mechanism_SFI = {}
mechanism_SFI["name"] = "SFI"
mechanism_SFI["tablename"] = "SFI"
mechanism_SFI["shortname"] = "sfi"
mechanism_SFI["Tunmed"] = {}
mechanism_SFI["Tunmed"]["read"] = 50
mechanism_SFI["Tunmed"]["write"] = 50
mechanism_SFI["Tunmed"]["call"] = 25
mechanism_SFI["Tunmed"]["return"] = 25
mechanism_SFI["Tunmed"]["free"] = 50
mechanism_SFI["Tmed"] = {}
mechanism_SFI["Tmed"]["read"] = 150
mechanism_SFI["Tmed"]["write"] = 150
mechanism_SFI["Tmed"]["call"] = 50
mechanism_SFI["Tmed"]["return"] = 50
mechanism_SFI["Tmed"]["free"] = 150
mechanism_SFI["Tunmed_ext_call"] = 25
mechanism_SFI["objmax"] = True
mechanisms.append(mechanism_SFI)

# SFI (optimized)
mechanism_SFI_opt = {}
mechanism_SFI_opt["name"] = "SFI_opt"
mechanism_SFI_opt["tablename"] = "SFI_opt"
mechanism_SFI_opt["shortname"] = "sfi_opt"
mechanism_SFI_opt["Tunmed"] = {}
mechanism_SFI_opt["Tunmed"]["read"] = 5
mechanism_SFI_opt["Tunmed"]["write"] = 5
mechanism_SFI_opt["Tunmed"]["call"] = 5
mechanism_SFI_opt["Tunmed"]["return"] = 5
mechanism_SFI_opt["Tunmed"]["free"] = 5
mechanism_SFI_opt["Tmed"] = {}
mechanism_SFI_opt["Tmed"]["read"] = 150
mechanism_SFI_opt["Tmed"]["write"] = 150
mechanism_SFI_opt["Tmed"]["call"] = 50
mechanism_SFI_opt["Tmed"]["return"] = 50
mechanism_SFI_opt["Tmed"]["free"] = 150
mechanism_SFI_opt["Tunmed_ext_call"] = 5
mechanism_SFI_opt["objmax"] = True
mechanisms.append(mechanism_SFI_opt)

# Capability hardware
mechanism_capability = {}
mechanism_capability["name"] = "Capability Hardware"
mechanism_capability["tablename"] = "Capability Hardware"
mechanism_capability["shortname"] = "capabilityhardware"
mechanism_capability["Tunmed"] = {}
mechanism_capability["Tunmed"]["read"] = 0
mechanism_capability["Tunmed"]["write"] = 0
mechanism_capability["Tunmed"]["call"] = 0
mechanism_capability["Tunmed"]["return"] = 0
mechanism_capability["Tunmed"]["free"] = 0
mechanism_capability["Tmed"] = {}
mechanism_capability["Tmed"]["read"] = 50
mechanism_capability["Tmed"]["write"] = 50
mechanism_capability["Tmed"]["call"] = 600
mechanism_capability["Tmed"]["return"] = 600
mechanism_capability["Tmed"]["free"] = 50
mechanism_capability["Tunmed_ext_call"] = 600
mechanism_capability["objmax"] = False
mechanisms.append(mechanism_capability)

# Direct hardware
mechanism_direct = {}
mechanism_direct["name"] = "Direct Hardware Support"
mechanism_direct["tablename"] = "Direct HW Support"
mechanism_direct["shortname"] = "directhardware"
mechanism_direct["Tunmed"] = {}
mechanism_direct["Tunmed"]["read"] = 0
mechanism_direct["Tunmed"]["write"] = 0
mechanism_direct["Tunmed"]["call"] = 0
mechanism_direct["Tunmed"]["return"] = 0
mechanism_direct["Tunmed"]["free"] = 0
mechanism_direct["Tmed"] = {}
mechanism_direct["Tmed"]["read"] = 10
mechanism_direct["Tmed"]["write"] = 10
mechanism_direct["Tmed"]["call"] = 10
mechanism_direct["Tmed"]["return"] = 10
mechanism_direct["Tmed"]["free"] = 10
mechanism_direct["Tunmed_ext_call"] = 10
mechanism_direct["objmax"] = False
mechanisms.append(mechanism_direct)

# This function estimates the cycles added by reference monitor via mediation, See uSCOPE 5.3.2.
def calculate_added_cycles(cmap, subject_clusters, object_clusters, linkmap, mechanism):

    added_cycles = 0
    
    for node in cmap.dg:
                        
        # Follow outgoing edges. Only instructions have successors.
	# Successors can be obj or instr.
        for obj_node in cmap.dg.successors(node):

            subj_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(node)]]
            
            if cmap.get_node_type(obj_node) == NodeType.OBJECT:
                obj_cluster = object_clusters[cmap.get_node_ip(obj_node)]
                
            elif cmap.get_node_type(obj_node) == NodeType.SUBJECT:
                obj_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(obj_node)]]
                
            edge = cmap.dg.get_edge_data(node, obj_node)

            # Handle read/write/free
            for op in ["read","write","free"]:
                if linkmap[subj_cluster][obj_cluster][op] == "unmediated":
                    added_cycles += edge[op] * mechanism["Tunmed"][op]
                elif linkmap[subj_cluster][obj_cluster][op] == "mediated":
                    added_cycles += edge[op] * mechanism["Tmed"][op]
                else:
                    if edge[op] > 0:
                        raise Exception("No linktype for nonzero edge " +
                                        linkmap[subj_cluster][obj_cluster][op])

            # Handle call/return
            for op in ["call", "return"]:
                if subj_cluster == obj_cluster:
                    added_cycles += edge[op] * mechanism["Tunmed"][op]
                elif linkmap[subj_cluster][obj_cluster][op] == "unmediated":
                    added_cycles += edge[op] * mechanism["Tunmed_ext_call"]
                elif linkmap[subj_cluster][obj_cluster][op] == "mediated":
                    added_cycles += edge[op] * mechanism["Tmed"][op]
                else:
                    if edge[op] > 0:
                        raise Exception("No linktype for nonzero edge.")

    return added_cycles

# Estimate the baseline cycles for a cmap, only used it we don't have a baseline file.
# The estimate is a cheesy projection based on the number of operations in that file.
def estimate_baseline(cmap):

    print("WARNING: estimating baseline.")
    
    num_heap = 0
    num_global = 0
    num_calls = 0
    for node in cmap.dg:
        for obj_node in cmap.dg.successors(node):
            edge = cmap.dg.get_edge_data(node, obj_node)           
            if cmap.get_node_type(obj_node) == NodeType.OBJECT and \
               cmap.get_node_memtype(obj_node) == MemType.HEAP:
                num_heap += edge["read"] + edge["write"]
            if cmap.get_node_type(obj_node) == NodeType.OBJECT and \
               (cmap.get_node_memtype(obj_node) == MemType.GLOBAL or
                cmap.get_node_memtype(obj_node) == MemType.SPECIAL):
                num_global += edge["read"] + edge["write"]
            if edge["call"] > 0:
                num_calls += edge["call"]

    #percent_heap = .17 
    #estimate = num_heap / percent_heap

    # Alternateivly, can estimate by rate of function calling
    estimate = num_calls * 150
    return estimate

# Calculate the overhead. Calls calculate_added_cycles() and divides by baseline cycles
def calculate_overhead(cmap, subject_clusters, object_clusters, linkmap, mechanism):

    if cmap.baseline_cycles != None:
        baseline = cmap.baseline_cycles
    else:
        baseline = estimate_baseline(cmap)
    
    added_cycles = calculate_added_cycles(cmap, subject_clusters, object_clusters,
                                          linkmap, mechanism)

    overhead = float(added_cycles) / baseline * 100.0
    
    return overhead

# Sweep mechanisms and cuts. Print table with results.
def calculate_overhead_for_cuts(capmap, cuts, cut_names):

    # Print header
    print("Mechanism".ljust(30) + "Compartments".ljust(15) + "Overhead".ljust(15))

    # This file by default calculates the unmediated, but one mediated overhead
    obj_map = cmap.obj_no_cluster
    
    for m in mechanisms:    
        for i in range(0, len(cuts)):
            linkmap = cmap.make_linkmap(cuts[i], obj_map, "unmediated")
            overhead = calculate_overhead(capmap, cuts[i], obj_map, linkmap, m, verbose=True)
            print(m["name"].ljust(30) +
                  cut_names[i].ljust(15)+
                  ('{:.1f}'.format(overhead * 100) + "%").ljust(15))
        print("")
    
if __name__ == '__main__':
    if len(sys.argv) > 2:
        
        # Default behavior for this file: read a kmap and compute the overhead
        # for each of the cuts and each hardware protection mechanism 
        cmap = CAPMAP(sys.argv[1], sys.argv[2])
        print("Calculating overhead...")
        calculate_overhead_for_cuts(cmap,
                                    [cmap.func_to_topdir, cmap.func_to_dir,
                                     cmap.func_to_file, cmap.func_to_func],
                                    ["TopDir", "Dir", "File", "Func"])
    else:
        print("Use python calculate_overhead.py <vmlinux> <kmap> to run on a .kmap")
