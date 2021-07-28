#!/usr/bin/python

# This file contains the logic to calculate privilege metrics given a CAPMAP and
# a particular decomposition (domain grouping).

# It can be run standalone to show syntactic metrics "python calculate_PS.py <vmlinux> <kmap>",
# but is primarily used by other components of uSCOPE.
# It computes the privilege set (PS), privilege set ratio (PSR),
# promiscuity metric (PM) and promiscuity metric ratio (PMR) for partitions.

from CAPMAP import *
import sys
import copy

# List of ops, ops_all includes combined readwrite
ops = ["read", "write", "call", "return", "free"]
ops_all = ops + ["readwrite"]

# When working with (and minimizing) PS, we occasionally require a single number that
# aggregates the various kinds of PS together (refered to as PS_total).
# A knob we can turn is how to weigh the various kinds of PS against each other.
# This simple function simply adds them (all weight of 1); a future exploration
# direction is applying various weighting schemes to guide the algorithms.
def calc_PS_total(PS):
    return PS["read"] + PS["write"] + PS["call"] + PS["return"] + PS["free"]

# Calculate PS_min for a cmap. Returns a dict indexed by op.
# PS_min is the privilege required by the program, so we simply
# follow the CAPMAP to see what was required.
def calculate_PSmin(cmap):
    
    PS_min = {}
    PS_min["read"] = 0
    PS_min["write"] = 0
    PS_min["readwrite"] = 0    
    PS_min["call"] = 0
    PS_min["return"] = 0
    PS_min["free"] = 0
    
    for node in cmap.dg:

        for obj_node in cmap.dg.successors(node):
            
            size = cmap.get_node_size(obj_node)
        
            edge = cmap.dg.get_edge_data(node, obj_node)
            
            for op in ops:
                PS_min[op] += size if edge[op] > 0 else 0
            PS_min["readwrite"]	+= size if (edge["write"] > 0 or edge["read"] > 0) else 0
            
    return PS_min
            
# Calculate the PS_mono for a cmap. Returns a dict indexed by op.
# This represents all the privilege in the system with no separation.
# At a high level, it's the number of instructions that can perform an
# op times the number of bytes that are accessible.
# This interpretation assumes that we might use an operation on anything
# (might call data, might write code, etc).
# Parameterizable by whether or not we model Write XOR Execute (WXORE),
# and whether we include or exclude dead code.
def calculate_PSmono(cmap, WXORE, LIVE):

    PS_mono = {}
    
    total_instr_size = 0
    num_reads = 0
    num_writes = 0
    num_calls = 0
    num_returns = 0    
    num_frees = 0
    total_entry_points = 0
    
    for f in cmap.functions:
        
        # Skip if we're removing dead and this is dead
        if LIVE and not f in cmap.live_functions:
            continue
        
        num_reads += cmap.instr_count_map[f]["read"]
        num_writes += cmap.instr_count_map[f]["write"]
        num_calls += cmap.instr_count_map[f]["call"]
        num_returns += cmap.instr_count_map[f]["return"]
        num_frees += cmap.instr_count_map[f]["free"]
        total_instr_size += cmap.instr_count_map[f]["size"]
        total_entry_points += 1
    
    # Count up the size of data objects
    total_data_size = 0
    for node in cmap.dg:
        if node[0] == NodeType.OBJECT:
            total_data_size += cmap.get_node_size(node)
            
    # Finally, calculate PS_mono. Depends on whether we model WXORE
    if WXORE:
        PS_mono["read"] = num_reads * (total_data_size + total_instr_size)
        PS_mono["write"] = num_writes * total_data_size
        PS_mono["readwrite"] = num_writes * total_data_size + num_reads * (total_data_size + total_instr_size)
        PS_mono["free"] = num_frees * total_data_size
        PS_mono["call"] = num_calls * total_instr_size
        PS_mono["return"] = num_returns * total_instr_size        
    else:
        PS_mono["read"] = num_reads * (total_data_size + total_instr_size)
        PS_mono["write"] = num_writes * (total_data_size + total_instr_size)
        PS_mono["readwrite"] = (num_reads + num_writes) * (total_data_size + total_instr_size)
        PS_mono["free"] = num_frees * (total_data_size + total_instr_size)
        PS_mono["call"] = num_calls * (total_data_size + total_instr_size)
        PS_mono["return"] = num_returns * (total_data_size + total_instr_size)
        
    return PS_mono


# As opposed to the simple PSmin or PSmono cases, we typically want to compute
# PS for a given set of subject and object domain clusters and a particular
# assignment of mediated/unmediated to each edge. This is computed here.
def calculate_PS_cluster_linkmap(cmap, subject_clusters, object_clusters, linkmap,
                                 WXORE=False, LIVE = False, return_sum=True, skip_special=False):

    # Calculating the PS for a cut efficiently involves pre-computing some intermediate state.
    # This includes:
    # 1) A cluster_size map that stores the size in bytes of each subject cluster
    # 2) An unmediated_accessible_size map that stores the amount of object data a cluster has unmediated access to
    # 3) A cluster_op_count map that stores how many ops of each kind are in each cluster
    # After calculating these things, we can walk the graph in O(V+E) and calculate the PS

    # Make a list of clusters
    clusters = set()
    for f in cmap.functions:
        clusters.add(subject_clusters[f])
            
    ### Step 1: Calculate the size of each code and object cluster. ###

    # Code clusters:
    code_cluster_sizes = {}
    for f in cmap.functions:

        # Add to cluster size
        cluster = subject_clusters[f]
        if not cluster in code_cluster_sizes:
            code_cluster_sizes[cluster] = 0

        # Skip if we're removing dead and this is dead
        if LIVE and not f in cmap.live_functions:
            continue            
            
        code_cluster_sizes[cluster] += cmap.instr_count_map[f]["size"]

    # Object clusters:
    obj_cluster_sizes = {}
    for node in cmap.dg:
        if node[0] == NodeType.OBJECT:
            obj_ip = cmap.get_node_ip(node)
            obj_cluster = object_clusters[obj_ip]
            if not obj_cluster in obj_cluster_sizes:
                obj_cluster_sizes[obj_cluster] = 0
            if skip_special and obj_ip in ["STACK", "VMEMMAP", "MEMBLOCK"]:
                continue
            obj_cluster_sizes[obj_cluster] += cmap.get_node_size(node)
        
    ### Step 2: Calculate unmediated_accessible_size for each op for each cluster ###

    # First calculate which objects and subjects are unmediated from each subject
    unmediated_accessible_objs = {}
    for node in cmap.dg:
        if node[0] == NodeType.SUBJECT:
            
            subj_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(node)]]
            
            if not subj_cluster in unmediated_accessible_objs:
                unmediated_accessible_objs[subj_cluster] = {}
                for op in ops:
                    unmediated_accessible_objs[subj_cluster][op] = set()

            for obj_node in cmap.dg.successors(node):

                if obj_node[0] == NodeType.SUBJECT:
                    obj_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(obj_node)]]
                elif obj_node[0] == NodeType.OBJECT:
                    obj_cluster = object_clusters[cmap.get_node_ip(obj_node)]

                edge = cmap.dg.get_edge_data(node, obj_node)                    
                for op in ops:
                    if edge[op] > 0:
                        if linkmap[subj_cluster][obj_cluster][op] == "unmediated":
                            unmediated_accessible_objs[subj_cluster][op].add(obj_cluster)
                    

    # Next, we can calculate the unmediated accessible size for each op type
    unmediated_accessible_size = {}
    for subj_cluster in clusters:
        
        unmediated_accessible_size[subj_cluster] = {}
        
        for op in ops_all:
            unmediated_accessible_size[subj_cluster][op] = 0
            
        if subj_cluster in unmediated_accessible_objs:

            for op in ops:
                
                for obj_cluster in unmediated_accessible_objs[subj_cluster][op]:

                    # For read/write/free, the size is the sum of the object cluster
                    # For call/return, the size is the size of the code
                    if op in ["read", "write", "free"]:
                        unmediated_accessible_size[subj_cluster][op] += obj_cluster_sizes[obj_cluster]
                    else:
                        unmediated_accessible_size[subj_cluster][op] += code_cluster_sizes[obj_cluster]
                        
            unmediated_accessible_size[subj_cluster]["readwrite"] += unmediated_accessible_size[subj_cluster]["read"] + \
                                                                     unmediated_accessible_size[subj_cluster]["write"]


    ### Step 3: Count the number of operations of each kind in each cluster ###
    
    cluster_op_counts = {}    
    for f in cmap.functions:
        
        subj_cluster = subject_clusters[f]
        if subj_cluster not in cluster_op_counts:
            cluster_op_counts[subj_cluster] = {}
            for op in ops_all:
                cluster_op_counts[subj_cluster][op] = 0
            cluster_op_counts[subj_cluster]["functions"] = 0

        # Skip if we're removing dead and this is dead
        if LIVE and not f in cmap.live_functions:
            continue
        
        cluster_op_counts[subj_cluster]["read"] += cmap.instr_count_map[f]["read"]
        cluster_op_counts[subj_cluster]["write"] += cmap.instr_count_map[f]["write"]
        cluster_op_counts[subj_cluster]["call"] += cmap.instr_count_map[f]["call"]
        cluster_op_counts[subj_cluster]["return"] += cmap.instr_count_map[f]["return"]
        cluster_op_counts[subj_cluster]["free"] += cmap.instr_count_map[f]["free"]
        cluster_op_counts[subj_cluster]["readwrite"] += cmap.instr_count_map[f]["read"] + cmap.instr_count_map[f]["write"]
        cluster_op_counts[subj_cluster]["functions"] += 1 

        
    # Step 4: With these data structures built, we can efficiently compute PS.
    # We know the size of each subject cluster and object cluster.
    # We know the number of ops of each type in each subject cluster.
    # And we know the unmediated accessible size for each op type for each subj cluster.
    
    # The PS arising from mediated and unmediated kinds of access are computed separately.
    PS_cut = {}
    PS_cut["read"] = {}
    PS_cut["write"] = {}
    PS_cut["readwrite"] = {}
    PS_cut["call"] = {}
    PS_cut["return"] = {}
    PS_cut["free"] = {} 

    # First we calculate unmediated PS.
    # Unmediated PS is computed by multiplying the number of ops in a cluster by the size of
    # data that is accessible unmediated from each cluster.
    # Made slightly more complex by the modeling of either W^X, simple CFI, both or neither.
    # Nick note: I might like accounting for WXORE and CFI by changing unmediated accessible size instead of here.
    for subj_cluster in cluster_op_counts:
        if WXORE:
            PS_cut["read"][subj_cluster] = cluster_op_counts[subj_cluster]["read"] * (unmediated_accessible_size[subj_cluster]["read"] + code_cluster_sizes[subj_cluster])
            PS_cut["readwrite"][subj_cluster] = cluster_op_counts[subj_cluster]["readwrite"] * unmediated_accessible_size[subj_cluster]["readwrite"]                
            PS_cut["write"][subj_cluster] = cluster_op_counts[subj_cluster]["write"] * unmediated_accessible_size[subj_cluster]["write"]
            PS_cut["free"][subj_cluster] = cluster_op_counts[subj_cluster]["free"] * unmediated_accessible_size[subj_cluster]["free"]
            PS_cut["call"][subj_cluster] = cluster_op_counts[subj_cluster]["call"] * unmediated_accessible_size[subj_cluster]["call"]
            PS_cut["return"][subj_cluster] = cluster_op_counts[subj_cluster]["return"] * unmediated_accessible_size[subj_cluster]["return"]
        else:
            PS_cut["read"][subj_cluster] = cluster_op_counts[subj_cluster]["read"] * (unmediated_accessible_size[subj_cluster]["read"] + code_cluster_sizes[subj_cluster])
            PS_cut["readwrite"][subj_cluster] = cluster_op_counts[subj_cluster]["readwrite"] * (unmediated_accessible_size[subj_cluster]["readwrite"] + code_cluster_sizes[subj_cluster])
            PS_cut["write"][subj_cluster] = cluster_op_counts[subj_cluster]["write"] * (unmediated_accessible_size[subj_cluster]["write"] + code_cluster_sizes[subj_cluster])
            PS_cut["free"][subj_cluster] = cluster_op_counts[subj_cluster]["free"] * (unmediated_accessible_size[subj_cluster]["free"] + code_cluster_sizes[subj_cluster])
            PS_cut["call"][subj_cluster] = cluster_op_counts[subj_cluster]["call"] * (unmediated_accessible_size[subj_cluster]["call"] + unmediated_accessible_size[subj_cluster]["read"])
            PS_cut["return"][subj_cluster] = cluster_op_counts[subj_cluster]["return"] * (unmediated_accessible_size[subj_cluster]["return"] + unmediated_accessible_size[subj_cluster]["read"])

    # Lastly, we compute mediated PS.
    # Mediated PS is computed by simply following the CAPMAP
    for node in cmap.dg:

        if node[0] == NodeType.SUBJECT:
            subj_ip = cmap.get_node_ip(node)
            subj_cluster = subject_clusters[cmap.ip_to_func[subj_ip]]
            
            # Only subjects have successors
            for obj_node in cmap.dg.successors(node):
                
                obj_ip = cmap.get_node_ip(obj_node)
                obj_size = cmap.get_node_size(obj_node)
                edge = cmap.dg.get_edge_data(node, obj_node)

                # Object/subject clustering depends on whether operating on instr/obj
                if obj_node[0] == NodeType.OBJECT:
                    obj_cluster = object_clusters[obj_ip]
                elif obj_node[0] == NodeType.SUBJECT:
                    obj_cluster = subject_clusters[cmap.ip_to_func[obj_ip]]

                for op in ops:
                    
                    link_type = linkmap[subj_cluster][obj_cluster][op]

                    # If mediated, only specific instruction can access this object cluster
                    # So add size of just this object
                    if link_type == "mediated":
                        size = obj_size
                        PS_cut[op][subj_cluster] += size if edge[op] > 0 else 0
                        if op in ["read", "write"]:
                            PS_cut["readwrite"][subj_cluster] += size if edge[op] > 0 else 0


    # We now have PS_cut calculated broken down by subj_cluster
    # We can either return this raw, or sum up all subj together
    if return_sum:
        PS_all = {}
        PS_all["read"] = 0
        PS_all["write"] = 0
        PS_all["readwrite"] = 0
        PS_all["call"] = 0
        PS_all["return"] = 0        
        PS_all["free"] = 0      

        for subj_cluster in clusters:
            for op in ops_all:
                PS_all[op] += PS_cut[op][subj_cluster]
    
        return PS_all
    
    else:
        return PS_cut

    
# Calculate_all_metrics fills up this table with entries, used to print out the PSR latex tables
psr_table = {}

# Calculate and print one case. Helper function for calculate_all_metrics().
def print_case(PS_min, PS_mono, PS, label, spc, op):
    PM = PS - PS_min
    PSR = float(PS) / PS_mono if PS_mono > 0 else 0
    PMR1 = float(PM) / PS_mono if PS_mono > 0 else 0
    PMR2 = float(PM) / PS_min if PS_min > 0 else 0    
    print(label.ljust(spc + 10) +
          '{:.3e}'.format(PS).ljust(spc) +
          '{:.7f}'.format(PSR).ljust(spc - 3) +
          '{:.3e}'.format(PM).ljust(spc) +
          '{:.3e}'.format(PMR1).ljust(spc) +
          '{:.1f}'.format(PMR2).ljust(spc))

    global psr_table
    name = label + "_" + op
    #print("Setting " + name + " to " + str(PSR))
    psr_table[name] = PSR
    
# Calculate metrics from a cmap and an optional list of cuts
def calculate_all_metrics(cmap, cuts, cut_names, obj_clustering):

    # First, compute all the PSs. Min, Mono and all the cuts we were asked for
    metric_results = []    
    print("Calculating metrics...")
    
    global psr_table
    psr_table = {}

    PS_min = calculate_PSmin(cmap)

    CFI=False
    WXORE=True
    
    # Calculate PS mono and add for various WXORE and CFI
    for WXORE in [False, True]:
        for LIVE in [False, True]:
            name = ""
            if WXORE:
                name += "(W^E)"
            if LIVE:
                name += "(live)"
            metric_results.append(("PSmono" + name, calculate_PSmono(cmap, WXORE, LIVE)))

    # PS_mono for reference when calculating PSR
    PS_mono = calculate_PSmono(cmap, False, False)

    # Add all the PSmins to the table
    for op in ops_all:
        psr_table["Instr_" + op] = float(PS_min[op]) / PS_mono[op]
    total_min = calc_PS_total(PS_min)
    total_mono = calc_PS_total(PS_mono)
    psr_table["Instr_total"] = float(total_min) / total_mono

    # Calculate PS for each of the requested cuts, including for each combination of WXORE and LIVE
    for i in range(0, len(cuts)):

        unmediated_linkmap = cmap.make_linkmap(cuts[i], obj_clustering, "unmediated")
        mediated_linkmap = cmap.make_linkmap(cuts[i], obj_clustering, "mediated")
        
        for WXORE in [False, True]:
            for LIVE in [False, True]:
                name = ""
                if WXORE:
                    name += "(W^E)"
                if LIVE:
                    name += "(live)"

                PS_unmediated = calculate_PS_cluster_linkmap(cmap, cuts[i], obj_clustering, unmediated_linkmap, WXORE, LIVE)
                metric_results.append((cut_names[i] + "(unmed)" + name, copy.deepcopy(PS_unmediated)))
                
                PS_mediated = calculate_PS_cluster_linkmap(cmap, cuts[i], obj_clustering, mediated_linkmap, WXORE, LIVE)
                metric_results.append((cut_names[i] + "(med)" + name, copy.deepcopy(PS_mediated)))

    metric_results.append(("PSmin", PS_min))    
    
    # Pretty print table
    spc=20
    for op in ops_all:
        # Print header        
        print("Op=" + op)
        print("Model".ljust(spc + 10) + "PS".ljust(spc) + "PSR".ljust(spc - 3) + "PM".ljust(spc) + "PMR1".ljust(spc) + "PMR2".ljust(spc))        

        for (label, ps) in metric_results:
            print_case(PS_min[op], PS_mono[op], ps[op], label, spc, op)

        # Print blank line between ops
        print("")


    print("Op=total")
    print("Model".ljust(spc + 10) + "PS".ljust(spc) + "PSR".ljust(spc - 3) + "PM".ljust(spc) + "PMR1".ljust(spc) + "PMR2".ljust(spc))        
    
    for (label, ps) in metric_results:
        print_case(calc_PS_total(PS_min), calc_PS_total(PS_mono), calc_PS_total(ps), label, spc, "total")

    print("")

    #for name in psr_table:
    #    print("PSR[" + name + "]=" + str(psr_table[name]))
    

if __name__ == '__main__':
    if len(sys.argv) > 2:
        cmap = CAPMAP(sys.argv[1], sys.argv[2])
        calculate_all_metrics(cmap, [cmap.func_to_topdir, cmap.func_to_dir, cmap.func_to_file, cmap.func_to_func],
                              ["TopDir", "Dir", "File", "Func"], cmap.obj_no_cluster)
    else:
        print("Use python calculate_PS.py <vmlinux> <kmap> to run on a .kmap")
