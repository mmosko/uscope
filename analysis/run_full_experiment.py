#!/usr/bin/python

# This file drives the overhead experiments

# Point these variables to training/overhead directories for evaluation:

# Trains on a pass of bare metal PHX + one combined LTP, each file scaled to equal weights
TRAIN_DIR="./data/RAID2021/training/"

# Currently the baremetal CAPMAPs
TEST_DIR="./data/RAID2021/overhead/"

import os

from CAPMAP import *
from DomainCreator import *
from calculate_PS import *
from calculate_overhead import *
from sweep_edge_assignment import *

if __name__ == '__main__':
    
    if len(sys.argv) > 0:

        # Can run in batch mode to run a single alpha value (for parallelism)
        if len(sys.argv) > 1:
            print("Running in batch mode!")
            ratio = float(sys.argv[1])
            print("Using ratio " + str(ratio))
            output = "output_raid_" + str(ratio) + "/"
            batch_mode = True
        # Otherwise, run all sequentially. Can take a long time if run on many cuts
        else:
            output = "output_raid"
            batch_mode = False

        if not os.path.exists(TRAIN_DIR):
            print("Error: couldn't find data directory " + str(TRAIN_DIR))
            sys.exit()
            
        # Settings
        WXORE = True

        # Make sure output dir exists
        if not os.path.exists(output):
            os.mkdir(output)

        ### Load in training CMAP, build our cuts based on those weights ###
        print("Step 1: Building the training CAPMAP...")
        cmap = CAPMAP(TRAIN_DIR + "vmlinux", TRAIN_DIR)
        
        print("Step 2: Running clustering algos to produce our cluster defs.")        
        # Syntatic experiments
        experiments = [("TopDir", cmap.func_to_topdir, cmap.obj_no_cluster), ("Dir", cmap.func_to_dir, cmap.obj_no_cluster),
                       ("File", cmap.func_to_file, cmap.obj_no_cluster), ("Func", cmap.func_to_func, cmap.obj_no_cluster)]

        # Full set of experiments:
        #ratios = [0.1, 0.01, 0.001, 0.0001, 0.00001, 0.000001, 0.0000005, 0.0000001, 0.00000005, 0.00000001, 0.000000005]

        # Faster set:
        ratios = [0.1, 0.01, 0.001, 0.0001, 0.00001, 0.000001, 0.0000005, 0.0000001]
        
        if batch_mode:
            (code_clusters, obj_clusters) = cluster_functions_and_objects(cmap, ClusterStrategy.CLUSTER_RATIO, ratio, False, 64)
            experiments += [("R" + str(ratio) +"_o64", code_clusters, obj_clusters), ("R" + str(ratio), code_clusters, cmap.obj_no_cluster)]
        else:
            for ratio in ratios:
                (code_clusters, obj_clusters) = cluster_functions_and_objects(cmap, ClusterStrategy.CLUSTER_RATIO, ratio, False, 64)
                experiments += [("R" + str(ratio) +"_o64", code_clusters, obj_clusters), ("R" + str(ratio), code_clusters, cmap.obj_no_cluster)]

        print("Step 3: Loading in all phoronix together for curve generation.")
        cmap_phx = CAPMAP(TEST_DIR + "vmlinux", TEST_DIR)

        # Next, load up single CAPMAPs for each of the benchmarks
        print("Step 4: Now loading individual phx CAPMAPs for overhead components...")
        benchmark_cmaps = []
        found_cmaps = 0
        for fname in os.listdir(TEST_DIR):
            if fname[-5:] == ".comp":
                print("Found benchmark! " + fname)
                bench_cmap = CAPMAP(TEST_DIR + "/vmlinux", TEST_DIR + "/" + fname, verbose=0, import_maps_from=cmap)
                if bench_cmap.baseline_cycles != None:
                    benchmark_cmaps.append(bench_cmap)
                    found_cmaps += 1
                else:
                    print("Skipping bench " + fname + ", no baseline cycles.")
                
            # Only load a subset of benchmark cmaps? Use for fast debugging
            #if found_cmaps >= 1:
            #    print("WARNING: only using a subset of benchmarks")
            #    break
        
        # Prepare output file
        print("Step 5: Running curve generation...")
        outfile = open(output + "edge_assignment_curves.txt", "w")
        outfile.write("# Created by by run_overhead_experiment.py\n")
        outfile.write("# mechanism cut num_unmediated overhead PS PSR ")
        for bench_cmap in benchmark_cmaps:
            outfile.write(bench_cmap.kmap_name.split(".")[0] + " ")
        outfile.write("\n")

        pointfile = open(output + "edge_assignment_points.txt", "w")
        pointfile.write("# Created by by run_overhead_experiment.py\n")                
        pointfile.write("# mechanism cut point_type overhead PSR\n")        

        for m in mechanisms:

            print("Running for mechanism " + m["name"])
            for (name, cut, objclustering) in experiments:
                print("\tRunning for cut " + name)
                
                # Skip some clustered conditions that we don't use: object clustering or not depending on mechanism
                if (name[0] == "C" or name[0] == "R") and m["objmax"]:
                    if not "_o64" in name:
                        print("Skipping " + name + " for mechanism " + m["shortname"] + "(requires obj clustering)")
                        continue
                    
                if (name[0] == "C" or name[0] == "R") and not m["objmax"]:
                    if "_o64" in name:
                        print("Skipping " + name + " for mechanism " + m["shortname"] + "(do not use obj clustering)")
                        continue
                
                trace_edge_assignment_curve(cmap_phx, cut, name, objclustering, m, outfile, pointfile, WXORE, benchmark_cmaps, return_at_level=None)
                
        outfile.close()

        print("Construct pareto curves...")
        outfile = open(output + "pareto_curves.txt", "w")        
        construct_pareto_curves(cmap_phx, outfile)
        
        # Close files and exit
        outfile.close()

    else:
        print("Use python run_full_experiment.py")
        print("See file for how to set up experiment dir.")
