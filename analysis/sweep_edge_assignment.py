#!/usr/bin/python

# This file takes as input a set of subject and object domains. It then traces out
# the tradeoff space that can be reached by various edge assignments of mediated/unmediated.
# 
# The full range of privilege/performance points are written out to a file for analysis.
#
# It follows the algorithm from Sec. 6.4 in the uSCOPE paper.

import os
import random
import datetime
import copy

from CAPMAP import *
from calculate_PS import *
from calculate_overhead import *
from DomainCreator import *
from calculate_ECR import *

# Debugging fuction to show the difference between two PSs.
def print_diff(PS1, PS2):
    diffread = PS1["read"] - PS2["read"]
    diffwrite = PS1["write"] - PS2["write"]
    diffcall = PS1["call"] - PS2["call"]
    diffreturn = PS1["return"] - PS2["return"]
    difffree = PS1["free"] - PS2["free"]                
    print(str(diffread) + "," + str(diffwrite) + "," + str(diffcall) +
          "," + str(diffreturn) + "," + str(difffree))
    
# For performance reasons, the edge assignment sweep computes deltas
# in PS and perf at each step. For debugging, a checkrate > 0 causes
# the running deltas to be computed from scratch and compared with
# the current sums to detect any logic errors. A check rate of 0.01
# means recheck 1% of steps. Has severe performance costs, debug only.
check_rate = 0

# Fill up this dict with data in addition to producing a datafile
# it's used to construct the pareto curve
edge_assignment_curves = {}

# Run the edge assignment algorithm and write the output to outfile.
# The outfile is written in a "melted" form for easy consumption in R.
# plot_edge_assignment_curve.R is one such visualation tool for this output
def trace_edge_assignment_curve(cmap, subject_clusters, cut_name, object_clusters,
                                mechanism, outfile, WXORE, benchmark_cmaps = [],
                                return_at_level=None):


    global edge_assignment_curves
    
    if WXORE == False:
        raise Exception("Error: edge assignment assumes WXORE.")

    if return_at_level != None:
        print("Edge sweep returning early at level: " + str(return_at_level))
    
    # Calculate range of PS for this cmap
    PS_mono = calculate_PSmono(cmap, WXORE, LIVE=False)
    PS_mono_total = calc_PS_total(PS_mono)
    PS_min = calculate_PSmin(cmap)
    PS_min_total = calc_PS_total(PS_min)    
    
    # Create initial linkmap, which is all-mediated.
    linkmap = cmap.make_linkmap(subject_clusters, object_clusters, "mediated")
    PS_start = calculate_PS_cluster_linkmap(cmap, subject_clusters, object_clusters,
                                            linkmap, WXORE=WXORE)

    # Endpoint linkmap. End of curve.
    linkmap_unmediated = cmap.make_linkmap(subject_clusters, object_clusters, "unmediated")
    PS_unmediated = calculate_PS_cluster_linkmap(cmap, subject_clusters, object_clusters,
                                                 linkmap_unmediated, WXORE=WXORE)

    # Count number of links we're about to assign a type to
    number_links = 0
    number_mediated_links = 0
    for subj_cluster in linkmap:
        for obj_cluster in linkmap[subj_cluster]:
            for op in ops:
                if linkmap[subj_cluster][obj_cluster][op] == "mediated":
                    number_links += 1
                    
    # Print out the mono, min and number of links for this sweep
    print("Running edge assignment on cut " + cut_name + " for mechanism " + mechanism["shortname"])
    print("\tPS statistics:")
    print("\tPS_mono: " + str(calc_PS_total(PS_mono)))
    print("\tPS_unmediated: " + str(calc_PS_total(PS_unmediated)))
    print("\tPS_mediated: " + str(calc_PS_total(PS_start)))    
    print("\tPS_min:" + str(calc_PS_total(PS_min)))
    print("\tNumber of links: " + str(number_links))

    # Calculate starting cycles for the cmap
    baseline = estimate_baseline(cmap)
    starting_cycles = calculate_added_cycles(cmap, subject_clusters, object_clusters,
                                             linkmap, mechanism)

    # If provided benchmarks, calculate those starting cycles as well
    benchmark_starting_cycles = []
    benchmark_baselines = []
    if len(benchmark_cmaps) > 0:
        print("Got a list of benchmark cmaps! Calculating starting overhead cycles.")        
        for bm_cmap in benchmark_cmaps:
            this_baseline = bm_cmap.baseline_cycles
            if this_baseline == None:
                raise Exception("Missing baseline for one of the benchmark cmaps!")
                #print("WARNING: no baseline cycles for " + bm_cmap.kmap_name + ", using estimate.")
                #this_baseline = estimate_baseline(bm_cmap)
            this_starting_cycles = calculate_added_cycles(bm_cmap, subject_clusters,
                                                          object_clusters, linkmap, mechanism)
            benchmark_baselines.append(this_baseline)
            benchmark_starting_cycles.append(this_starting_cycles)
    
    # Build some data structures that we will use:
    # 1) We'll keep track of which objects are in which object clusters
    # 2) and which instructions access which object clusters.

    # Create empty sets for these
    obj_cluster_to_obj = {}
    accessing_instructions = {}
    for i in object_clusters:
        c = object_clusters[i]
        if not c in obj_cluster_to_obj:
            obj_cluster_to_obj[c] = set()
            accessing_instructions[c] = set()
    for i in subject_clusters:
        c = subject_clusters[i]
        if not c in obj_cluster_to_obj:
            obj_cluster_to_obj[c] = set()
            accessing_instructions[c] = set()

    # For fast call/return mediation, precalculate all the calls and returns
    # in each cluster
    calls_in_cluster = {}
    returns_in_cluster = {}
    for subj_cluster in linkmap:
        calls_in_cluster[subj_cluster] = set()
        returns_in_cluster[subj_cluster] = set()
    for node in cmap.dg:
        if node[0] == NodeType.OBJECT:
            continue
        src_ip = cmap.get_node_ip(node)
        src_func = cmap.ip_to_func[src_ip]
        src_cluster = subject_clusters[src_func]
        for obj_node in cmap.dg.successors(node):
            if obj_node[0] == NodeType.OBJECT:
                continue
            dest_ip = cmap.get_node_ip(obj_node)            
            edge = cmap.dg.get_edge_data(node, obj_node)
            if edge["call"] > 0:
                calls_in_cluster[src_cluster].add(node)
            if edge["return"] > 0:
                returns_in_cluster[src_cluster].add(node)
                    
    # Collect the objects in each cluster
    for node in cmap.dg:
        for obj_node in cmap.dg.successors(node):
            # Skip over instrs
            if obj_node[0] != NodeType.OBJECT:
                continue
            obj_cluster = object_clusters[cmap.get_node_ip(obj_node)]
            obj_cluster_to_obj[obj_cluster].add(obj_node)

    # Collect the instructions that access each object cluster.
    # We need later for computing deltas.
    for obj_cluster in obj_cluster_to_obj:
        for obj in obj_cluster_to_obj[obj_cluster]:
            for instr_node in cmap.dg.predecessors(obj):
                accessing_instructions[obj_cluster].add(instr_node)

    # Next, compute some of the stats we will need:
    # 1) The size of each object cluster
    # 2) The number of operations of each kind in each cluster
    
    # Count size of each object cluster
    obj_cluster_sizes = {}    
    for op in ["read", "write", "free"]:
        obj_cluster_sizes[op] = {}        
        for node in cmap.dg:
            if node[0] != NodeType.OBJECT:
                continue
            obj_cluster = object_clusters[cmap.get_node_ip(node)]        
            if not obj_cluster in obj_cluster_sizes[op]:
                obj_cluster_sizes[op][obj_cluster] = 0

            this_obj_size = cmap.get_node_size(node)

            # If there is a weight on this object, use to scale the object cluster size
            weights = cmap.dg.node[node]["weight"]
            this_weight = 1
            if op == "read":
                this_weight = weights[0]
            elif op == "write":
                this_weight = weights[1]
            else:
                this_weight = weights[2]
            this_obj_size *= this_weight
            
            obj_cluster_sizes[op][obj_cluster] += this_obj_size

    # Compute the op count of each cluster
    cluster_op_counts = {}
    clusters = {}
    for f in cmap.functions:
        subj_cluster = subject_clusters[f]
        if not subj_cluster in clusters:
            clusters[subj_cluster] = set()
        clusters[subj_cluster].add(f)
        if subj_cluster not in cluster_op_counts:
            cluster_op_counts[subj_cluster] = {}
            cluster_op_counts[subj_cluster]["size"] = 0
            for op in ops_all:
                cluster_op_counts[subj_cluster][op] = 0
                
        cluster_op_counts[subj_cluster]["read"] += cmap.instr_count_map[f]["read"]
        cluster_op_counts[subj_cluster]["write"] += cmap.instr_count_map[f]["write"]
        cluster_op_counts[subj_cluster]["call"] += cmap.instr_count_map[f]["call"]
        cluster_op_counts[subj_cluster]["return"] += cmap.instr_count_map[f]["return"]
        cluster_op_counts[subj_cluster]["free"] += cmap.instr_count_map[f]["free"]
        cluster_op_counts[subj_cluster]["readwrite"] += cmap.instr_count_map[f]["read"] + \
                                                        cmap.instr_count_map[f]["write"]
        cluster_op_counts[subj_cluster]["size"] += cmap.instr_count_map[f]["size"]
        
    # We have now built 4 data structures we need:
    # 1) An obj cluster to obj map
    # 2) A map of the set of instructions that access each obj cluster
    # 3) The size of each obj cluster
    # 4) The number of operations of each kind in each cluster
    # With that, we are ready to run the edge assignment algorithm!
    
    # We will add the information about each link to this list, and then sort it.
    # Entries are tuples (perf/PS ratio, cycles saved, PS increase, subj_cluster, obj_cluster)
    downgrade_links = []
            
    # This loop calculates the delta PS and delta cycles added for all links
    for subj_cluster in linkmap:

        for obj_cluster in linkmap[subj_cluster]:

            # Consider downgrading links for any of these ops. Now complete set.
            for op in ["read", "write", "free", "call", "return"]:

		# Can only downgrade existing mediated links
		if linkmap[subj_cluster][obj_cluster][op] == "mediated":

                    # Skip
                    if op in ["call", "return"]:
                        if subj_cluster == obj_cluster:
                            raise Exception("mediated self call?")
                            print("Skipping call or return self-edge.")
                            
                    # There are two things to compute about a link:
                    # (1) the cycle savings and (2) the PS increase.
                    
		    # Step 1: Find the number of cycles we would save
		    # Collect the number of accesses to this object cluster by the subj_cluster
		    # whose link we may downgrade. These are the accesses we would save.
                    saved_ops = 0

                    # And a list for each of the benchmark cmaps
                    saved_ops_benchmarks = [0] * len(benchmark_cmaps)

                    if op in ["read", "write", "free"]:
                        savings_per_unit = (mechanism["Tmed"][op] - mechanism["Tunmed"][op])
                        # We're looking for instructions in the instr cluster that access the
                        # object cluster in question. The weight on those edges represents how
                        # much we would save = weight * diff between mediated and unmediated.
                        # Free nodes have both call edges (to code) and access edges (to objs)
                        for i in accessing_instructions[obj_cluster]:
                            instr_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(i)]]
                            if instr_cluster == subj_cluster:
                                for obj in cmap.dg.successors(i):
                                    # This filters out free nodes which have instr successors
                                    if obj[0] == NodeType.OBJECT:
                                        this_obj_cluster = object_clusters[cmap.get_node_ip(obj)]
                                        if this_obj_cluster == obj_cluster:
                                            edge = cmap.dg.get_edge_data(i, obj)
                                            saved_ops += edge[op]

                                            # Similarly, compute the saved cycles for each of the benchmark cmaps
                                            for j in range(0, len(benchmark_cmaps)):
                                                bm_cmap = benchmark_cmaps[j]
                                                if bm_cmap.dg.has_node(i):
                                                    if bm_cmap.dg.has_node(obj):
                                                        if bm_cmap.dg.has_edge(i,obj):
                                                            bm_edge = bm_cmap.dg.get_edge_data(i, obj)                                                    
                                                            saved_ops_benchmarks[j] += bm_edge[op]
                    elif op in ["call", "return"]:
                        savings_per_unit = mechanism["Tmed"][op] - mechanism["Tunmed_ext_call"]
                        # The performance calc is pretty simple: all call/ret edges from subj to obj that are currently
                        # mediated gain the savings of becoming unmediated
                        number_calls_in_cluster = 0
                        if op == "call":
                            nodes = calls_in_cluster[subj_cluster]
                        else:
                            nodes = returns_in_cluster[subj_cluster]
                            
                        for instr_node in nodes:
                            # Find all edges to correct dest cluster
                            for dest_node in cmap.dg.successors(instr_node):
                                if dest_node[0] == NodeType.OBJECT:
                                    continue
                                dest_node_ip = cmap.get_node_ip(dest_node)
                                dest_cluster = subject_clusters[cmap.ip_to_func[dest_node_ip]]
                                if dest_cluster == obj_cluster:
                                    edge = cmap.dg.get_edge_data(instr_node, dest_node)
                                    saved_ops += edge[op]

                                    # Compute savings for all other benchmarks
                                    for j in range(0, len(benchmark_cmaps)):
                                        bm_cmap = benchmark_cmaps[j]
                                        if bm_cmap.dg.has_node(instr_node):
                                            if bm_cmap.dg.has_node(dest_node):
                                                if bm_cmap.dg.has_edge(instr_node, dest_node):
                                                    bm_edge = bm_cmap.dg.get_edge_data(instr_node, dest_node)
                                                    saved_ops_benchmarks[j] += bm_edge[op]
                        
		    # Num_accesses is the number of edges that are about to go from external to internal.
		    # Some mechanisms (SFI) still charge for internal, so the _difference_ between
                    # external and internal * num accesses is the savings.
		    estimated_savings = saved_ops * savings_per_unit

                    # Similarly, compute savings for each of the benchmarks
                    savings_benchmarks = []
                    for s in saved_ops_benchmarks:
                        this_savings = s * savings_per_unit
                        savings_benchmarks.append(this_savings)

                    # We now have computed how many cycles we would save by making this link unmediated.
		    # Check if the actual savings == estimated savings by recomputing from scratch.
		    # This check is disabled when not debugging.
		    if check_rate > 0 and random.random() < check_rate:
		        baseline_cycles = calculate_added_cycles(cmap, subject_clusters, object_clusters, linkmap, mechanism)
		        linkmap[subj_cluster][obj_cluster][op] = "unmediated"
		        actual_cycles = calculate_added_cycles(cmap, subject_clusters, object_clusters, linkmap, mechanism)
		        actual_savings = baseline_cycles - actual_cycles
		        if not actual_savings == estimated_savings:
		            print("Estimate on saved cycles = " + str(estimated_savings))
		            print("Actual savings: " + str(actual_savings))                    
		            print("Not the same! Diff:" + str(actual_savings - estimated_savings))
		            raise Exception("Performance recalculation different from delta")
		        else:
		            print("Passed perf check. " + subj_cluster + " to " + obj_cluster + " " + op)
		        linkmap[subj_cluster][obj_cluster][op] = "mediated"

		    # Step 2: Find the increase in PS we would incur
		    # Need to know the current priv that results from the link, and what the priv would become
		    # if unmediated.

                    if op in ["read", "write", "free"]:
                        # Unmediated PS calculation is simple. This is what will happen to PS if we unmediate.
                        unmediated_PS = cluster_op_counts[subj_cluster][op] * obj_cluster_sizes[op][obj_cluster]

                        # In addition to unmediated PS, we need to know current mediated PS so we can compute difference.
                        # Current PS from the link involves tracing over all involved edges.
                        current_PS = 0

                        # Only count instructions actually in instr_cluster accessing objects
                        # actually in obj_cluster
                        for i in accessing_instructions[obj_cluster]:
                            instr_cluster = subject_clusters[cmap.ip_to_func[cmap.get_node_ip(i)]]
                            if instr_cluster == subj_cluster:
                                for obj in cmap.dg.successors(i):
                                    if obj[0] != NodeType.OBJECT:
                                        continue
                                    this_obj_cluster = object_clusters[cmap.get_node_ip(obj)]
                                    if this_obj_cluster == obj_cluster:
                                        this_obj_size = cmap.get_node_size(obj)

                                        # Account for object weights
                                        weights = cmap.dg.node[obj]["weight"]
                                        this_weight = 1;
                                        if op == "read":
                                            this_weight = weights[0]
                                        elif op == "write":
                                            this_weight = weights[1]
                                        else:
                                            this_weight = weights[2]
                                        this_obj_size *= this_weight

                                        # Add to PS
                                        edge = cmap.dg.get_edge_data(i, obj)
                                        current_PS  += this_obj_size if edge[op] > 0 else 0                    

                        estimate_increase_PS = unmediated_PS - current_PS

                    # TODO: make work for WXORE = False
                    elif op in ["call", "return"]:
                        
                        # Unmediated PS calc is simple: all call/ret can now go to dest
                        unmediated_PS = cluster_op_counts[subj_cluster][op] * cluster_op_counts[obj_cluster]["size"]
                        # Then subtract from that all calls/rets that currently do have that priv
                        current_PS = 0
                        
                        if op == "call":
                            nodes = calls_in_cluster[subj_cluster]
                        else:
                            nodes = returns_in_cluster[subj_cluster]
                            
                        for instr_node in nodes:
                            
                            # Find all edges to correct dest cluster
                            for dest_node in cmap.dg.successors(instr_node):
                                if dest_node[0] == NodeType.OBJECT:
                                    continue
                                dest_node_ip = cmap.get_node_ip(dest_node)
                                dest_cluster = subject_clusters[cmap.ip_to_func[dest_node_ip]]
                                if dest_cluster == obj_cluster:
                                    edge = cmap.dg.get_edge_data(instr_node, dest_node)
                                    current_PS += cmap.get_node_size(dest_node) if edge[op] > 0 else 0
                                    
                        estimate_increase_PS = unmediated_PS - current_PS
                        

		    # Check the actual PS increase matches delta. Only for debugging.
		    if check_rate > 0 and random.random() < check_rate:                
		        baseline_PS = calculate_PS_cluster_linkmap(cmap, subject_clusters, object_clusters, linkmap, WXORE)
		        baseline_PS_total = calc_PS_total(baseline_PS)
		        linkmap[subj_cluster][obj_cluster][op] = "unmediated"
		        increase_PS = calculate_PS_cluster_linkmap(cmap, subject_clusters, object_clusters, linkmap, WXORE)
		        increase_PS_total = calc_PS_total(increase_PS)
		        actual_increase_PS = increase_PS_total - baseline_PS_total
		        if not actual_increase_PS == estimate_increase_PS:
		            #print_diff(baseline_PS, current_PS)
                            print("Estimate increase: " + str(estimate_increase_PS) + ", actual increase=" + str(actual_increase_PS))
		            print("Not the same!")
                            print("Op=" + op)
                            print("Diff=" + str(actual_increase_PS - estimate_increase_PS))
		            print("Subj_cluster=" + subj_cluster + " obj_cluster=" + obj_cluster)
		            raise Exception("PS recalculation different from delta")                        
		        else:
		            print("Passed PS check. " + subj_cluster + " to " + obj_cluster + " " + op)
		        linkmap[subj_cluster][obj_cluster][op] = "mediated"

                    if estimated_savings > 0:
		        ratio = float(estimated_savings) / estimate_increase_PS if estimate_increase_PS > 0 else 0
		        downgrade_links.append((ratio, estimated_savings, estimate_increase_PS, subj_cluster, obj_cluster, op, savings_benchmarks))

    # We now have the deltas for all links, sort them for greedy algorithm.
    # This comparison operator sorts potential links to downgrade.
    # Ratio of 0 beats any number, if tied at 0, choose best savings.
    # Otherwise highest ratio wins.
    def compare_links((r1, s1, p1, subj1, obj1, op1, savings_bms1), (r2, s2, p2, subj2, obj2, op2, savings_bms2)):
        if r1 == 0 and r2 == 0:
            if s1 < s2:
                return 1
            else:
                return -1
        elif r1 == 0:
            return -1
        elif r2 == 0:
            return 1
        else:
            if r1 > r2:
                return -1
            else:
                return 1
    downgrade_links.sort(compare_links)

    # We now have a sorted list of preferred links to downgrade. Take one by one and create data file.
    running_linkmap = cmap.make_linkmap(subject_clusters, object_clusters, "mediated")
    run_id = mechanism["shortname"] + ":" + cut_name
    edge_assignment_curves[run_id] = []
    num_unmediated = 0    
    
    # Track PS as we go along curve
    current_PS = calc_PS_total(PS_start)
    current_PSR = float(current_PS) / PS_mono_total
    starting_PS = current_PS

    # Track overhead as we go along curve. Also track for all of the benchmarks
    current_cycles = starting_cycles
    overhead = float(current_cycles) / baseline * 100.0
    
    benchmark_cycles = []
    benchmark_overheads = []    
    for i in range(0, len(benchmark_cmaps)):
        benchmark_cycles.append(benchmark_starting_cycles[i])
        benchmark_overhead = float(benchmark_cycles[i]) / benchmark_baselines[i] * 100.0
        benchmark_overheads.append(benchmark_overhead)

    if len(benchmark_cmaps) > 0:
        average_ovhd = float(sum(benchmark_overheads)) / len(benchmark_overheads)
    else:
        average_ovhd = overhead

    # Configure number of benchmarks to include in result file.
    num_display_benches = 5
    
    # Write out first line, which is before any links are downgraded to unmediated.    
    outfile.write(mechanism["shortname"] + "\t" + cut_name + "\t" + str(num_unmediated) +
                  "\t" + str(average_ovhd) + "\t" + str(current_PS) + "\t" + str(current_PSR))
    for i in range(0, len(benchmark_cmaps)):
        if num_display_benches != None and i > num_display_benches:
            continue
        outfile.write("\t" + str(benchmark_overheads[i]))
    outfile.write("\t" + str(overhead))
    outfile.write("\n")

    edge_assignment_curves[run_id].append((average_ovhd, current_PS, current_PSR))

    last_written_overhead = None

    if return_at_level != None:
        half_unmediation_point = int(len(downgrade_links) * return_at_level)
        if half_unmediation_point == 0:
            half_unmediation_point = 1
        print("Half unmediation point: " + str(half_unmediation_point))
        
    print("Number of links: " + str(number_links))
    
    # Then finally process all of the links one by one!
    for (ratio, savings, PSincr, subj, obj, op, bench_savings) in downgrade_links:

        running_linkmap[subj][obj][op] = "unmediated"
        
        # Compute PS updates for taking this link as unmediated
        num_unmediated += 1
        current_PS += PSincr
        current_PSR = float(current_PS) / PS_mono_total
        current_PMR = float(current_PS) / PS_min_total
        
        # Compute overhead for main cmap
        current_cycles -= savings
        overhead = float(current_cycles) / baseline * 100.0

        # Compute overhead for benchmark cmaps
        benchmark_overheads = []
        for i in range(0, len(benchmark_cmaps)):
            benchmark_cycles[i] -= bench_savings[i]
            benchmark_overhead = float(benchmark_cycles[i]) / benchmark_baselines[i] * 100.0
            benchmark_overheads.append(benchmark_overhead)

        if len(benchmark_cmaps) > 0:
            average_ovhd = float(sum(benchmark_overheads)) / len(benchmark_overheads)
        else:
            average_ovhd = overhead

        # If returning a linkmap at a specific point, return here
        if return_at_level != None and num_unmediated == half_unmediation_point:
            print("Reached target unmediation point! Returning here.")
            return (running_linkmap, average_ovhd, current_PMR)

        # Determine if we write this line or not (minimum delta of 0.005)
        writing = False
        if last_written_overhead == None or (last_written_overhead - average_ovhd > 0.005):
            writing = True
            outfile.write(mechanism["shortname"] + "\t" + cut_name + "\t" + str(num_unmediated) + "\t" + str(average_ovhd) + "\t" + str(current_PS) + "\t" + str(current_PSR))
            last_written_overhead = average_ovhd

        if writing:
            written = 0
            for bo in benchmark_overheads:
                outfile.write("\t" + str(bo))
                written += 1
                if num_display_benches != None and written > num_display_benches:
                    break
            outfile.write("\t" + str(overhead))
            outfile.write("\n")

        edge_assignment_curves[run_id].append((average_ovhd, current_PS, current_PSR))

    print("Finished edge assignment curve.")

# Construct pareto-optimal curves over all sweeps
def construct_pareto_curves(cmap, outfile):
    
    global edge_assignment_curves

    outfile.write("#mechanism overhead PS PSR source_cut\n")

    # Save this as a backup
    edge_curve_file = open("edge_assignment_curves_saved.txt", "w")
    edge_curve_file.write(str(edge_assignment_curves))

    # Collect all the points for each mechanism, then create pareto
    possible_points = {}
    for run_id in edge_assignment_curves.keys():
        m = run_id.split(":")[0]
        cut = run_id.split(":")[1]    
        curve = edge_assignment_curves[run_id]
        if not m in possible_points:
            possible_points[m] = []
        for (ovhd, PS, PSR) in curve:
            possible_points[m].append((PS, ovhd, PSR, cut))

    print("Done constructing and sorting lists")
    
    # Now construct each pareto curve, mechanism by mechanism
    for m in possible_points.keys():
        
        print("Constructing for mechanism " + m)
        
        points = sorted(possible_points[m])

        if len(points) < 1:
            print("Skipping mechanism " + m + ", not enough points.")
            continue

        last_overhead_written = None

        for (PS, ovhd, PSR, cut) in points:
            
            if last_overhead_written == None or last_overhead_written > ovhd:
                outfile.write(m + "\t" + str(ovhd) + "\t" + str(PS) + "\t" + str(PSR) + "\t" + cut + "\n")
                last_overhead_written = ovhd

        
if __name__ == '__main__':

    
    if len(sys.argv) > 2:

        # Configure output dir
        output = "edge_assignment_results/"
        if not os.path.exists(output):
            os.mkdir(output)
        
        # Setting WXORE
        WXORE = True
        
        # Load in CAPMAP
        cmap = CAPMAP(sys.argv[1], sys.argv[2])

        # Reset curves
        edge_assignment_curves = {}
                
        # Prepare output file
        outfile = open(output + "edge_assignment_curves.txt", "w")
        outfile.write("# Created for CAPMAP: " + sys.argv[2] + " by sweep_edge_assignment.py\n")
        outfile.write("# mechanism cut num_unmediated overhead PS PSR\n")

        # Prepare experiments to run. Start with the 3 of the syntactic cases
        experiments = [(cmap.func_to_topdir, "TopDir"), (cmap.func_to_dir, "Dir"),
                       (cmap.func_to_file, "File")]

        # Add a couple algorithmic domains
        for size in [1024, 2048, 4096, 8192]:
            subj_clusters = cluster_functions(cmap, ClusterStrategy.CLUSTER_SIZE, size)
            experiments.append((subj_clusters, "C" + str(size)))

        # Compute curves for these domains
        for (domains, name) in experiments:
            trace_edge_assignment_curve(cmap, domains, name, cmap.obj_no_cluster,
                                        mechanisms[1], outfile, WXORE)
                
        outfile.close()

        outfile = open(output + "pareto_curves.txt", "w")
        construct_pareto_curves(cmap, outfile)
        
    else:
        print("Use python sweep_edge_assignment.py <vmlinux> <kmap>")
