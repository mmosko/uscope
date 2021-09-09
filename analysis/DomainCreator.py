#!/usr/bin/python

# The DomainCreator contains algorithms for generating compartmentalizations
# algorithmically. As opposted to the syntactic domains, the algorithmic domains
# have the freedom to rearrange code and data in new ways to achieve much tighter
# compartmentalizations at lower cost.
#
# The output of the DomainCreator is subj_domain and obj_domain mappings that
# can be consumed by other uSCOPE tools just like any other kind of domain.
#
# The Domain Creator is invoked like so:
# subj_domains = cluster_functions(cmap, settings...)
# or
# (subj_domains, object_domains) = cluster_functions_and_objects(cmap, settings...)
#
# The DomainCreator currently supports two algorithmic approaches: CLUSTER_SIZE
# and CLUSTER_RATIO which follow the same general flow but use different utility
# function for choosing domains to merge.
#
# The domains are also written in the cluster_output directory for inspection.

from CAPMAP import *
from calculate_PS import *
from calculate_overhead import *
from calculate_ECR import *
import random
    
# DomainCreator supports two algorithms:
# 1) CLUSTER_SIZE, in which clusters are built based on size
# 2) CLUSTER_RATIO, in which clusters are built on a cost/benefit ratio
class ClusterStrategy(Enum):
    CLUSTER_SIZE = 1
    CLUSTER_RATIO = 2

# The size algorithm has a couple configurations:
SIZE_CONFIG_WEIGHT_PER_INSTR=True
SIZE_CONFIG_REWARD_OBJ_MERGE=True

class DomainCreator:

    def __init__(self, cmap):

        # The CAPMAP graph object that we are running clustering algorithms on
        self.cmap = cmap
        
        # A map that records which cluster each function currently belongs to
        self.function_assignment = {}

        # A set of current clusters, stored as lists e.g., clusters[c] = [f1, f2 ... fn]
        self.clusters = {}

        # A set of object clusters (only set if run with object clustering)
        self.obj_clusters = None

        # A map of which objects are accessed by each function per op type
        self.accessed_objs = {}
        for op in ["read", "write", "free"]:
            self.accessed_objs[op] = {}

        # A map of which functions are called by each function
        self.called_funcs = {}

        # Clusters that are done merging
        self.finished_clusters = set()
        
        # A running total of each cluster's current size
        self.cluster_sizes = {}
        
        # A cache of reachable objects from each cluster
        self.reachable_objects_cache = {}
        
        # A cache of reachable subjects from each cluster
        self.reachable_clusters_cache = {}

        # A cache of the calls saved if we merged c1 and c2
        self.external_calls_saved = {}        
        
        # A switch to control how we count cluster size. Values are "instr" or "func".
        # "func" mostly deprecated now.
        self.SIZE_METRIC="instr"

    # Given a cluster, return which other clusters can be called from that cluster
    def reachable_clusters(self, c):
    
        # First, find all functions called by functions in this cluster
        all_called_funcs = set()
        for f in self.clusters[c]:
            if f in self.called_funcs:
                for called_f in self.called_funcs[f]:
                    all_called_funcs.add(called_f)

        # Then, take union of all of these clusters
        all_called_clusters = set()
        for f in all_called_funcs:
            cluster = self.function_assignment[f]
            if cluster != c and not cluster in self.finished_clusters:
                all_called_clusters.add(cluster)
        return all_called_clusters


    # Given a cluster, return a set of all objects accessed by that cluster
    def reachable_objs(self, c, op):

        reachable_objs = set()

        for f in self.clusters[c]:
            if f in self.accessed_objs[op]:
                for o in self.accessed_objs[op][f]:
                    reachable_objs.add(o)

        return reachable_objs


    # Recompute the reachability cache after changing cluster c
    def recompute_reachable_cache(self, c):
        for cluster in self.reachable_clusters_cache:
            if c in self.reachable_clusters_cache[cluster]:
                self.reachable_clusters_cache[cluster] = self.reachable_clusters(cluster)

    # Merge two clusters. Logically put c2 into c1.
    # 1) Remove c2 from cluster list, add those functions into c1
    # 2) Update function_assignment
    # 3) Recompute sizes and update caches
    def merge_clusters(self, c1, c2):

        #print("\tMerging a cluster with " + str(len(self.clusters[c1])) + \
        #      " functions and a cluster with " + str(len(self.clusters[c2])) + \
        #      " " + c1 + " " + c2)
        
        for f in self.clusters[c2]:
            self.function_assignment[f] = c1
            self.clusters[c1].append(f)

        # Update sizes and operation counts as a result of the merge
        self.cluster_sizes[c1] += self.cluster_sizes[c2]
        self.cluster_sizes[c2] = 0
        self.cluster_read_ops[c1] += self.cluster_free_ops[c2]
        self.cluster_write_ops[c1] += self.cluster_write_ops[c2]
        self.cluster_free_ops[c1] += self.cluster_free_ops[c2]                
        self.cluster_read_ops[c2] = 0
        self.cluster_write_ops[c2] = 0
        self.cluster_free_ops[c2] = 0
        self.cluster_call_ops[c1] += self.cluster_call_ops[c2]
        self.cluster_call_ops[c2] = 0

        # Clear out cluster c2
        self.clusters[c2] = []
        
        # Update caches
        for op in ["read", "write", "free"]:
            self.reachable_objects_cache[op][c2] = set()
            self.reachable_objects_cache[op][c1] = self.reachable_objs(c1,op)

        self.reachable_clusters_cache[c2] = set()
        self.reachable_clusters_cache[c1] = self.reachable_clusters(c1)

        # Now rebuild other parts of the caches that are affected by this merge.
        # 1) C2 should have no reachable, already set above.
        # 2) C1 should be recomputed now that C2 is in it, as done above.
        # 3) Reachable clusters changed because new edges, recalculate those now.
        for c in self.reachable_clusters_cache:
            # Skip the ones we just merged
            if c == c1 or c == c2:
                continue
            # Add new reachability from the merge
            if c2 in self.reachable_clusters_cache[c]:
                self.reachable_clusters_cache[c] = self.reachable_clusters(c)
        
        # Lastly, we need to update the external_calls_saved to each reachable cluster.

        # Update the counts on each edge outgoing from C1
        self.external_calls_saved[c1] = {}
        for new_cluster in self.reachable_clusters_cache[c1]:
            self.external_calls_saved[c1][new_cluster] = self.count_external_calls_saved(c1, new_cluster)

        # And also edges pointing back in.
        # Reachability not a mirror relation so it's not just opposite of above
        for search_cluster in self.clusters:
            if search_cluster == c1 or search_cluster == c2:
                continue
            # If we find c1, update it
            if c1 in self.reachable_clusters_cache[search_cluster]:
                self.external_calls_saved[search_cluster][c1] = self.count_external_calls_saved(search_cluster, c1)

    # Count the number of calls that are currently external between c1 and c2
    def count_external_calls_saved(self, c1, c2):

        total_external_calls_saved = 0
        
        # That includes c1 -> c2
        for f1 in self.clusters[c1]:
            if f1 in self.called_funcs:
                for f2 in self.called_funcs[f1]:
                    f2_cluster = self.function_assignment[f2]
                    if f2_cluster == c2:
                        total_external_calls_saved += self.called_funcs[f1][f2]

        # and c2 -> c1
        for f1 in self.clusters[c2]:
            if f1 in self.called_funcs:
                for f2 in self.called_funcs[f1]:
                    f2_cluster = self.function_assignment[f2]
                    if f2_cluster == c1:
                        total_external_calls_saved += self.called_funcs[f1][f2]

        return total_external_calls_saved

    
    def cluster_functions(self, cmap, strategy, strategy_param, pack_dead, extra_name=""):

        # Reset state for this run
        self.function_assignment = {}
        self.accessed_objs = {}
        self.reachable_objects_cache = {}
        self.accessed_objs = {}
        for op in ["read", "write", "free"]:
            self.accessed_objs[op] = {}
            self.reachable_objects_cache[op] = {}
        self.called_funcs = {}
        self.clusters = {}
        self.finished_clusters = set()
        self.cluster_sizes = {}
        self.cluster_call_ops = {}
        self.cluster_read_ops = {}
        self.cluster_write_ops = {}
        self.cluster_free_ops = {}        
        self.reachable_clusters_cache = {}
        self.external_calls_saved = {}
        self.smallest_cluster_size = None

        # Banner for this clustering run. Display the chosen config options.
        print("Running code clustering algorithm. Parameters:")
        
        if strategy == ClusterStrategy.CLUSTER_SIZE:
            print("Clustering strategy: cluster_size")
            cluster_size = strategy_param
            print("Cluster_size=" + str(cluster_size))            
        elif strategy == ClusterStrategy.CLUSTER_RATIO:
            print("Clustering strategy: cluster_ratio")
            cutoff_ratio = strategy_param
            print("Ratio_minimum=" + str(cutoff_ratio))            
            
        print("Pack clusters to full=" + str(pack_dead))

        # Make list of dead functions, we skip these in clustering and add them back at the end
        dead_functions = set()
        for f in self.cmap.functions:
            if not f in self.cmap.live_functions:
                dead_functions.add(f)

        # Create initial clusters, one function per cluster.
        # Set sizes and begin tracking the smallest cluster for later.
        cluster_id = 0
        for f in self.cmap.live_functions:
            cluster_id += 1
            cluster_name = "c" + str(cluster_id)
            self.clusters[cluster_name] = [f]
            self.function_assignment[f] = cluster_name
            # With a plain vmlinux, we have real sizes. Without, approximate 2X bloat
            if self.cmap.has_plain_vmlinux:
                function_size = int(self.cmap.instr_count_map[f]["size"])
            else:
                function_size = int(self.cmap.instr_count_map[f]["size"]/2)
                
            self.cluster_sizes[cluster_name] = function_size
            self.cluster_read_ops[cluster_name] = self.cmap.instr_count_map[f]["read"]
            self.cluster_write_ops[cluster_name] = self.cmap.instr_count_map[f]["write"]
            self.cluster_free_ops[cluster_name] = self.cmap.instr_count_map[f]["free"]
            self.cluster_call_ops[cluster_name] = self.cmap.instr_count_map[f]["call"] + \
                                                  self.cmap.instr_count_map[f]["return"]

            if self.smallest_cluster_size == None or function_size < self.smallest_cluster_size:
                self.smallest_cluster_size = function_size

        #print("Minimum cluster size: " + str(self.smallest_cluster_size))
        
        # Step 1: Build two data structures that track info about the functions.
        # Also count up total number of calls, used by ratio clusterer.
        # Also log each object size, used by the ratio clusterer
        total_calls = 0
        object_sizes = {}
        for op in ["read", "write", "free"]:
            object_sizes[op] = {}
            
        for node in self.cmap.dg:

            if cmap.get_node_type(node) == NodeType.SUBJECT:

                instr_ip = self.cmap.get_node_ip(node)
                instr_func = self.cmap.ip_to_func[instr_ip]

                if not instr_func in self.accessed_objs["read"]:
                    for op in ["read", "write", "free"]:
                        self.accessed_objs[op][instr_func] = set()
                    self.called_funcs[instr_func] = {}

                for obj_node in self.cmap.dg.successors(node):

                    edge = self.cmap.dg.get_edge_data(node, obj_node)
                    obj_ip = self.cmap.get_node_ip(obj_node)

                    if cmap.get_node_type(obj_node) == NodeType.SUBJECT:

                        called_func = self.cmap.ip_to_func[obj_ip]

                        if not called_func in self.called_funcs[instr_func]:
                            self.called_funcs[instr_func][called_func] = 0
                        self.called_funcs[instr_func][called_func] += edge["call"] + edge["return"]

                        total_calls += edge["call"] + edge["return"]

                    elif cmap.get_node_type(obj_node) == NodeType.OBJECT:
                        obj_cluster = obj_ip
                        for op in ["read", "write", "free"]:
                            if edge[op] > 0:
                                self.accessed_objs[op][instr_func].add(obj_cluster)
                        
            elif cmap.get_node_type(node) == NodeType.OBJECT:

                obj_ip = self.cmap.get_node_ip(node)
                size = self.cmap.dg.node[node]["size"]
                weight = self.cmap.dg.node[node]["weight"]
                object_sizes["read"][obj_ip] = size * weight[0]
                object_sizes["write"][obj_ip] = size * weight[1]
                object_sizes["free"][obj_ip] = size * weight[2]

        # Step 2: Build reachable objects cache
        # clusters that are still smaller than cluster_size can be merged        
        still_can_merge = set()
        for c in self.clusters:
            still_can_merge.add(c)
            for op in ["read", "write", "free"]:
                self.reachable_objects_cache[op][c] = self.reachable_objs(c, op)
            self.reachable_clusters_cache[c] = self.reachable_clusters(c)

        # Step 3: Precompute the external calls saved for each pair of functions
        for c1 in self.clusters:
            for c2 in self.reachable_clusters_cache[c1]:
                if not c1 in self.external_calls_saved:
                    self.external_calls_saved[c1] = {}
                self.external_calls_saved[c1][c2] = self.count_external_calls_saved(c1, c2)

        # This is the core loop of the algorithm. In its current form, it is inefficient.
        # We consider all possible merges, take the best, and then repeat.
        merge_step = 0
        while True:
            merge_step += 1
            if merge_step % 32 == 0:
                print("\tCode clustering step " + str(merge_step))

            # Keep track of best merge we've found
            best_merge = None
            best_merge_score = -1
            best_merge_ps_increase = -1
            best_merge_ratio = -1
            best_calls_saved = -1

            # Loop over all possible cluster to cluster merges
            for c1 in still_can_merge:
                
                for c2 in self.reachable_clusters_cache[c1]:

                    if not c2 in still_can_merge:
                        continue
                    
                    if strategy == ClusterStrategy.CLUSTER_SIZE:
                        
                        # First, check if this merge is legal in terms of size constraints
                        if self.SIZE_METRIC == "func":
                            if (len(self.clusters[c1]) + len(self.clusters[c2])) > cluster_size:
                                continue
                        elif self.SIZE_METRIC == "instr":
                            if self.cluster_sizes[c1] + self.cluster_sizes[c2] > cluster_size:
                                continue

                        # Next, check how many new objects are introduced
                        objs1 = self.reachable_objects_cache["read"][c1].union(
                            self.reachable_objects_cache["write"][c1]).union(
                                self.reachable_objects_cache["free"][c1])
                        count1 = len(objs1)

                        objs2 = self.reachable_objects_cache["read"][c2].union(
                            self.reachable_objects_cache["write"][c2]).union(
                                self.reachable_objects_cache["free"][c2])                        
                        count2 = len(objs2)

                        union = objs1.copy()
                        for o in objs2:
                            union.add(o)

                        merged_count = len(union)

                        # Count the number of new object introductions
                        objects_added = len(union - objs1) + len(union - objs2)

                        # This merge is a valid candidate merge. Calculate benefit.
                        total_external_calls_saved = self.external_calls_saved[c1][c2]

                        benefit = total_external_calls_saved
                        
                        merge_score = total_external_calls_saved

                        # If rewarding obj merges, favor ratio of saved cycles to objs added
                        if SIZE_CONFIG_REWARD_OBJ_MERGE:
                            merge_score = merge_score / (objects_added + 1)

                        # If calculating weight per instr to prefer smaller funcs, adjust score here
                        if SIZE_CONFIG_WEIGHT_PER_INSTR:
                            size_increase = (self.cluster_sizes[c1] + self.cluster_sizes[c2]) - \
                                            max(self.cluster_sizes[c1], self.cluster_sizes[c2])
                            merge_score = merge_score / size_increase

                    elif strategy == ClusterStrategy.CLUSTER_RATIO:

                        # For the ratio strategy, we compute the benefit/cost ratio,
                        # then stop when the ratio is not at least at some threshold.
                        
                        # Calculate benefit: the percent of saved calls. Multiplying by 1M
                        # so that ratio is really megaPS per call saved
                        total_external_calls_saved = self.external_calls_saved[c1][c2]

                        '''
                        # Check on call saved cache
                        if random.random() < 0.1:
                            recheck = self.count_external_calls_saved(c1, c2)
                            if recheck != total_external_calls_saved:
                                print("Error: Cached value did not match recalculation.")
                        '''
                        
                        benefit = float(total_external_calls_saved) * 1000000 / total_calls

                        # Calculate cost: the total PS increase of the merge.
                        # We break this down into call_PS and data_PS then sum them

                        # Calculate call/return PS increase:
                        # each call instr can now target all instructions in the other cluster
                        call_PS = self.cluster_call_ops[c1] * self.cluster_sizes[c2] + \
                                  self.cluster_call_ops[c2] * self.cluster_sizes[c1]
                        
                        # Calculate data PS. This is a little more complicated.
                        # Determine which objects accessible to each side (represented as sets)
                        objs1_read = self.reachable_objects_cache["read"][c1]
                        objs1_write = self.reachable_objects_cache["write"][c1]
                        objs1_free = self.reachable_objects_cache["free"][c1]
                        
                        objs2_read = self.reachable_objects_cache["read"][c2]
                        objs2_write = self.reachable_objects_cache["write"][c2]
                        objs2_free = self.reachable_objects_cache["free"][c2]

                        # Next, union these together, then subtract to determine what will be new
                        union_read = objs1_read.union(objs2_read)
                        union_write = objs1_write.union(objs2_write)
                        union_free = objs1_free.union(objs2_free)
                        
                        new_for_cluster1_read = union_read.difference(objs1_read)
                        new_for_cluster1_write = union_write.difference(objs1_write)
                        new_for_cluster1_free = union_free.difference(objs1_free)
                        
                        new_for_cluster2_read = union_read.difference(objs2_read)
                        new_for_cluster2_write = union_write.difference(objs2_write)
                        new_for_cluster2_free = union_free.difference(objs2_free)
                                                
                        # Calculate PS updates by introduced bytes for each op type to each side
                        new_for_cluster1_read_size = 0
                        new_for_cluster1_write_size = 0
                        new_for_cluster1_free_size = 0
                        for o in new_for_cluster1_read:
                            new_for_cluster1_read_size += object_sizes["read"][o]
                        for o in new_for_cluster1_write:
                            new_for_cluster1_write_size += object_sizes["write"][o]
                        for o in new_for_cluster1_free:
                            new_for_cluster1_free_size += object_sizes["free"][o]

                        new_for_cluster2_read_size = 0
                        new_for_cluster2_write_size = 0
                        new_for_cluster2_free_size = 0
                        for o in new_for_cluster2_read:
                            new_for_cluster2_read_size += object_sizes["read"][o]
                        for o in new_for_cluster2_write:
                            new_for_cluster2_write_size += object_sizes["write"][o]
                        for o in new_for_cluster2_free:
                            new_for_cluster2_free_size += object_sizes["free"][o]
                            
                        # Multiply ops by new bytes to get PS increase
                        data_PS = self.cluster_read_ops[c1] * new_for_cluster1_read_size + \
                                  self.cluster_write_ops[c1] * new_for_cluster1_write_size + \
                                  self.cluster_free_ops[c1] * new_for_cluster1_free_size + \
                                  self.cluster_read_ops[c2] * new_for_cluster2_read_size + \
                                  self.cluster_write_ops[c2] * new_for_cluster2_write_size + \
                                  self.cluster_free_ops[c2] * new_for_cluster2_free_size
                        
                        # Cost is full PS increase
                        cost = call_PS + data_PS
                        
                        merge_score = float(benefit) / cost

                        # Skip this merge if didn't meet cutoff
                        if merge_score < cutoff_ratio:
                            continue

                    # Lastly, track if this is best merge or not
                    if benefit > 0 and (best_merge == None or merge_score > best_merge_score):
                        best_merge_score = merge_score
                        best_calls_saved = total_external_calls_saved
                        best_merge = (c1, c2)

            if best_merge == None:
                print("No more valid merges! Done with code clustering.")
                break

            # Take out best candidate merge and perform the merging.
            # Merge c2 into c1.
            c1,c2 = best_merge

            # Print the merge?
            '''
            print("Merging " + c1 + " and " + c2 + " with score " + str(best_merge_score))
            print("\tSaves " + str(best_calls_saved) + " external calls.")
            print(c1 + "=")
            for f in sorted(self.clusters[c1]):
                print("\t" + f)
            print(c2 + "=")
            for f in sorted(self.clusters[c2]):
                print("\t" + f)            
            '''

            self.merge_clusters(c1,c2)

            self.finished_clusters.add(c2)

            # C2 is gone now, remove from list
            still_can_merge.remove(c2)

            # If C1 is full, or close enough that even the smallest merge would go over,
            # then remove that too.
            if strategy == ClusterStrategy.CLUSTER_SIZE:
                if self.SIZE_METRIC == "func":
                    if len(self.clusters[c1]) >= cluster_size:
                        #print("\tCluster " + c1 + " is full.")
                        still_can_merge.remove(c1)
                        self.finished_clusters.add(c1)
                        self.recompute_reachable_cache(c1)
                if self.SIZE_METRIC == "instr":
                    if (self.cluster_sizes[c1] + self.smallest_cluster_size) >= cluster_size:
                        #print("\tCluster " + c1 + " is full.")
                        still_can_merge.remove(c1)
                        self.finished_clusters.add(c1)
                        self.recompute_reachable_cache(c1)                        


        ### Clustering is now finished! Now do cleanup ###
        
        # Add in the dead functions now, one per cluster. We skipped these earlier to not slow
        # down the clustering. However, we want final map to be complete.
        dead_clusters = set()
        for f in dead_functions:
            cluster_id += 1
            cluster_name = "c" + str(cluster_id)
            dead_clusters.add(cluster_name)
            self.clusters[cluster_name] = [f]
            self.function_assignment[f] = cluster_name
            if self.cmap.has_plain_vmlinux:
                self.cluster_sizes[cluster_name] = int(self.cmap.instr_count_map[f]["size"])
            else:
                self.cluster_sizes[cluster_name] = int(self.cmap.instr_count_map[f]["size"]/2)
            still_can_merge.add(cluster_name)
            self.cluster_read_ops[cluster_name] = self.cmap.instr_count_map[f]["read"]
            self.cluster_write_ops[cluster_name] = self.cmap.instr_count_map[f]["write"]
            self.cluster_free_ops[cluster_name] = self.cmap.instr_count_map[f]["free"]            
            self.cluster_call_ops[cluster_name] = self.cmap.instr_count_map[f]["call"] + \
                                                  self.cmap.instr_count_map[f]["return"]
            for op in ["read", "write", "free"]:
                self.reachable_objects_cache[op][cluster_name] = self.reachable_objs(cluster_name, op)
            self.reachable_clusters_cache[cluster_name] = self.reachable_clusters(cluster_name)
            

        # If we are configured to pack dead functions, do so now.
        # Take each function that is alone, and begin packing them into clusters that can take them.
        # Take from the bottom of the list, and put next open slot that can take it.
        # Only merge dead with dead.
        if pack_dead and strategy == ClusterStrategy.CLUSTER_SIZE:
            print("Packing was turned on. Now filling up clusters despite no weighted call/ret edges.")
            c1_list = list(still_can_merge)
            random.shuffle(c1_list)
            for c1 in c1_list:
                # If removed while as a c2, skip
                if not c1 in still_can_merge:
                    continue
                if not c1 in dead_clusters:
                    continue
                if self.cluster_sizes[c1] < cluster_size:
                    open_clusters = list(still_can_merge)
                    random.shuffle(open_clusters)
                    for c2 in open_clusters:
                        if not c2 in dead_clusters:
                            continue
                        if c1 == c2:
                            continue
                        if (self.cluster_sizes[c1] + self.cluster_sizes[c2]) <= cluster_size:
                            self.merge_clusters(c1,c2)
                            self.finished_clusters.add(c2)
                            still_can_merge.remove(c2)
                            continue


        # Write the clusters to a file for easy inspection of results
        clusterfile_name = self.get_output_filename(strategy, strategy_param, extra_name)
        clusterfile = open(clusterfile_name, "w")
        self.write_clusters_to_file(cmap, clusterfile)

        # Sanity check: functions in clusters are right number (i.e., we accounted for all functions)
        total_funcs = 0
        for c in self.clusters:
            for f in self.clusters[c]:
                total_funcs += 1
        if not total_funcs == len(self.cmap.functions):
            raise Exception("Mismatch. Found " + str(total_funcs) + " instead of " + str(len(self.cmap.functions)))
        
        # Convert clustering into function-level map
        func_to_cluster = {}
        for f in self.cmap.functions:
            cluster = self.function_assignment[f]
            func_to_cluster[f] = cluster

        # Print ECR
        ecr = calculate_ECR(cmap, func_to_cluster)
        print("This clustering produced an ECR of " + str(ecr))

        # Print number of live clusters
        live_clusters = set()
        for f in cmap.live_functions:
            c = func_to_cluster[f]
            live_clusters.add(c)
        print("Number of live clusters: " + str(len(live_clusters)))
        
        return func_to_cluster
    
    # Helper function for cluster_objs. Classifies an object
    # into a type. Only objects of the same type can be grouped together
    def get_object_class(self, obj_name):
        if ".LC" in obj_name:
            return "LC"
        elif "KMEM" in obj_name:
            return "KMEM"
        elif "KMALLOC" in obj_name:
            return "KMALLOC"
        elif "ALLOC_PAGES" in obj_name:
            return "PAGE"
        elif "VMALLOC" in obj_name:
            return "VMALLOC"
        elif "STACK_FRAME" in obj_name:
            return "STACK_FRAME"
        elif "STACK_ARGS" in obj_name:
            return "STACK_FRAME"
        elif "GLOBAL_" in obj_name:
            if "|R" in obj_name:
                return "GLOBAL_R"
            elif "|D" in obj_name:
                return "GLOBAL_D"
            elif "|B" in obj_name:
                return "GLOBAL_B"
            else:
                return "GLOBAL"
        elif "code_fff" in obj_name:
            return "CODE"
        else:
            # Anything else we won't group
            return "SPECIAL"
    
    # A simple obj clustering algorithm. This is an independent-phase algorithm.
    # For each cluster over the limit, we iteratively merge objects that impact total PS
    # across all clusters the least.
    def cluster_objs(self, cmap, subj_clusters, OBJ_MAX, strategy, strategy_param, extra_name=""):

        print("Running new obj clustering! OBJ_MAX=" + str(OBJ_MAX))

        # Create the obj clustering map by starting with the no cluster map
        # Then, we will slowly remap some of these to new shared symbols
        obj_clusters = cmap.obj_no_cluster.copy()

        # Obj_cluster_map is a mapping from obj cluster names to the constintuent objects
        obj_cluster_map = {}

        # For the first phase, we only care about clusters that have > OBJ_MAX objects. Rest don't matter.
        clusters_over = set()
        objects_in_cluster = {}

        # Create a copy of the objects in each cluster, starting from the reachable objects cache
        for c in self.clusters:
            # Collect up all the objects reachable from this cluster across read/write/free
            all_objects = self.reachable_objects_cache["read"][c]
            all_objects = all_objects.union(self.reachable_objects_cache["write"][c])
            all_objects = all_objects.union(self.reachable_objects_cache["free"][c])            
            num_objs = len(all_objects)
            if num_objs > OBJ_MAX:
                print("Cluster " + c + " has " + str(num_objs) + " objs.")
                clusters_over.add(c)
            # Get objects from all clusters, even if not over, because we use later
            objects_in_cluster[c] = all_objects

        # We only group objects of the same type. Classify all objects now.
        all_objects = set()
        for c in objects_in_cluster:
            for o in objects_in_cluster[c]:
                all_objects.add(o)
                
        object_class = {}
        object_sizes = {}
        for op in ["read", "write", "free"]:
            object_sizes[op] = {}
        for o in all_objects:
            obj = cmap.get_object(o)
            obj_name = cmap.dg.node[obj]["name"]
            object_class[o] = self.get_object_class(obj_name)
            weights = cmap.dg.node[obj]["weight"]
            object_sizes["read"][o] = cmap.dg.node[obj]["size"] * weights[0]
            object_sizes["write"][o] = cmap.dg.node[obj]["size"] * weights[1]
            object_sizes["free"][o] = cmap.dg.node[obj]["size"] * weights[2]

        # With clusters_over computed, we can now begin the outer loop of the phase 1 algorithm
        next_obj_cluster_id = 0

        # Loop over each cluster that is over, do a single merge on that cluster then move on to next
        print("Running object clustering...")
        step_number = 0
        while True:
            
            if len(clusters_over) == 0:
                print("No more clusters over! Exiting object clustering.")
                break

            step_number += 1
            print("Object clustering step " + str(step_number) + \
                  ". Number of clusters over: " + str(len(clusters_over)))

            for c in list(clusters_over):
                
                # Build some maps:
                # 1) Which object groups are accessed by each cluster (nontrivial, changes as we group objects) = object_groups_in_cluster[c]
                # 2) Which clusters access each object group (nontrivial, changes as we group objects) = accessing_clusters[o]
                # Each of these indexed by op type, and also "all" for union of all op types
                accessing_clusters = {}
                object_groups_in_cluster = {}
                for op in ["read", "write", "free", "all"]:
                    accessing_clusters[op] = {}
                    object_groups_in_cluster[op] = {}
                
                for search_cluster in objects_in_cluster:

                    object_groups_in_cluster["all"][search_cluster] = set()
                    
                    for op in ["read", "write", "free"]:
                        
                        object_groups_in_cluster[op][search_cluster] = set()
                        
                        for o in self.reachable_objects_cache[op][search_cluster]:
                            
                            this_obj_cluster = obj_clusters[o]
                            
                            object_groups_in_cluster[op][search_cluster].add(this_obj_cluster)
                            object_groups_in_cluster["all"][search_cluster].add(this_obj_cluster)
                            
                            if not this_obj_cluster in accessing_clusters[op]:
                                accessing_clusters[op][this_obj_cluster] = set()
                            accessing_clusters[op][this_obj_cluster].add(search_cluster)
                            
                            if not this_obj_cluster in accessing_clusters["all"]:
                                accessing_clusters["all"][this_obj_cluster] = set()
                            accessing_clusters["all"][this_obj_cluster].add(search_cluster)

                # Compute size of each cluster
                object_cluster_sizes = {}
                for op in ["read", "write", "free"]:
                    object_cluster_sizes[op] = {}
                for o in all_objects:
                    #print("obj=" + o)
                    cluster = obj_clusters[o]
                    if not cluster in object_cluster_sizes["read"]:
                        object_cluster_sizes["read"][cluster] = 0
                        object_cluster_sizes["write"][cluster] = 0
                        object_cluster_sizes["free"][cluster] = 0
                    for op in ["read", "write", "free"]:
                        object_cluster_sizes[op][cluster] += object_sizes[op][o]

                merges_needed = len(object_groups_in_cluster["all"][c]) - OBJ_MAX
                #print("\tMerges needed: " + str(merges_needed))            
                if merges_needed <= 0:
                    print("\tCluster has been fixed! Removing from search: " + c)
                    clusters_over.remove(c)
                    continue

                best1 = None
                best2 = None
                best_cost = None
                
                # If we find a cost 0, take a fast path out and stop searching
                shortcut = False
                
                # Now loop over all pairs of objects in this cluster.
                # Only consider same-class merges.

                # Randomize inner and outer order. Otherwise, you start
                # digging deeper and deeper for the fast paths, etc
                this_obj_groups1 = list(object_groups_in_cluster["all"][c])
                this_obj_groups2 = list(object_groups_in_cluster["all"][c])
                random.shuffle(this_obj_groups1)                
                random.shuffle(this_obj_groups2)                
                
                for obj1 in this_obj_groups1:

                    # Exit fast path if we found a cost 0
                    if shortcut:
                        break
                    
                    # Calculate the class of obj1. Skip special objects.
                    if obj1[0] == "O":
                        obj1_class = object_class[obj_cluster_map[obj1][0]]
                    else:
                        obj1_class = object_class[obj1]                        
                    
                    if obj1_class == "SPECIAL":
                        continue
                        
                    for obj2 in this_obj_groups2:

                        # Can't do self-merges
                        if obj1 == obj2:
                            continue
                        
                        # Calculate the class of obj2. Skip special objects.
                        if obj2[0] == "O":
                            obj2_class = object_class[obj_cluster_map[obj2][0]]
                        else:
                            obj2_class = object_class[obj2]
                        
                        if obj2_class == "SPECIAL":
                            continue

                        # Additional constraint: only merge objects of the same class
                        if obj1_class != obj2_class:
                            continue

                        # If we merge these two object classes together, then several things happen:
                        # 1) We might open up new operation type links. If a non-writable and a writeable object
                        # merge, the result is writeable.
                        # 2) New code can possibly reach the resulting cluster, bringing the read/writes/frees from the other
                        # code into the picture.

                        access_obj1 = accessing_clusters["all"][obj1]
                        access_obj2 = accessing_clusters["all"][obj2]

                        increase_PS = 0
                        for op in ["read", "write", "free"]:
                            
                            access_obj1 = accessing_clusters[op][obj1] if obj1 in accessing_clusters[op] else set()
                            access_obj2 = accessing_clusters[op][obj2] if obj2 in accessing_clusters[op] else set()
                            union = access_obj1.union(access_obj2)
                            new_obj1 = union.difference(access_obj1)
                            new_obj2 = union.difference(access_obj2)
                            
                            for c in new_obj1:
                                for f in self.clusters[c]:
                                    increase_PS += cmap.instr_count_map[f][op] * object_cluster_sizes[op][obj1]

                            for c in new_obj2:
                                for f in self.clusters[c]:
                                    increase_PS += cmap.instr_count_map[f][op] * object_cluster_sizes[op][obj2]

                        cost = increase_PS                        

                        if best_cost == None or cost < best_cost:
                            best_cost = cost
                            best1 = obj1
                            best2 = obj2
                            #print("\tUpdating, found new best. " + obj1 + " " + obj2 + " " + obj1_class + " " + str(best_cost))

                            if cost == 0:
                                shortcut = True
                                break

                if best1 == None or best2 == None:
                    print("\tDid not find valid obj1 and obj2 to merge in this phase. Exiting.")
                    continue

                #if best_cost > 0:
                #    print("\tPicked merging " + best1 + " and " + best2 + " in cluster" + c + " with exposure cost of " + str(best_cost))
                #else:
                #    print("\tPicked merging " + best1 + " and " + best2 + " in cluster" + c + ", was free internal. Cost = " + str(best_cost))

                # Make a list of all primitive objects in these clusters
                objs = []
                for this_obj in [best1, best2]:
                    # Cluster case
                    if this_obj[0] == "O":
                        for o in obj_cluster_map[this_obj]:
                            objs.append(o)
                    # Single object case                    
                    else:
                        objs.append(this_obj)

                # Construct a new identifier
                new_cluster_name = "O" + str(next_obj_cluster_id)
                next_obj_cluster_id += 1

                # Update obj_cluster_map, use list() to make copy
                obj_cluster_map[new_cluster_name] = list(objs)

                # Update obj_cluster
                for o in objs:
                    obj_clusters[o] = new_cluster_name

        print("Finished object clustering!")
        self.obj_clusters = obj_clusters
        self.obj_cluster_map = obj_cluster_map

        # Overwrite cluster file from code clustering with new object clusters
        clusterfile_name = self.get_output_filename(strategy, strategy_param, extra_name)
        clusterfile = open(clusterfile_name, "w")
        self.write_clusters_to_file(cmap, clusterfile)
        
        # Return the obj clustering we have created
        return obj_clusters

    # Determine filename based on a strategy + params
    def get_output_filename(self, strategy, strategy_param, extra_name):
        
        clusterfile_name = "cluster_output/clusters_"
        if strategy == ClusterStrategy.CLUSTER_SIZE:
            clusterfile_name += "size_"
        if strategy == ClusterStrategy.CLUSTER_RATIO:
            clusterfile_name += "ratio_"
        clusterfile_name += str(strategy_param)
        if extra_name != "":
            clusterfile_name +="_" + extra_name
        return clusterfile_name

    def get_obj_name(self, o):
        if o in self.cmap.object_names:
            name = self.cmap.object_names[o]
        else:
            name = o
        return name
        
    # Write the resulting clusters to a file for inspection
    def write_clusters_to_file(self, cmap, clusterfile):
        print("Writing resulting domains to " + clusterfile.name)
        # Recompute obj reachability (only needed if we did object clustering)
        objs_accessed_cluster = {}
        for node in cmap.dg:
            if cmap.get_node_type(node) == NodeType.SUBJECT:
                subj_ip = cmap.get_node_ip(node)
                subj_cluster = self.function_assignment[cmap.ip_to_func[subj_ip]]
                if not subj_cluster in objs_accessed_cluster:
                    objs_accessed_cluster[subj_cluster] = set()
                for obj_node in cmap.dg.successors(node):
                    if cmap.get_node_type(obj_node) != NodeType.OBJECT:
                        continue
                    obj_ip = cmap.get_node_ip(obj_node)
                    if self.obj_clusters == None:
                        obj_cluster = obj_ip
                    else:
                        obj_cluster = self.obj_clusters[obj_ip]                        
                    objs_accessed_cluster[subj_cluster].add(obj_cluster)
        
        clusterfile.write("Final clusters:\n")
        index = 0
        sizes = []
        max_size = 0
        for c in self.clusters:

            if c in objs_accessed_cluster:
                objs = objs_accessed_cluster[c]
            else:
                objs = set()
            
            if len(self.clusters[c]) > 1:
                if len(self.clusters[c]) > 1:
                    sizes.append(self.cluster_sizes[c])
                if self.cluster_sizes[c] > max_size:
                    max_size = self.cluster_sizes[c]
                index += 1
                
                clusterfile.write("Compartment " + str(index) + "\n")
                clusterfile.write("\tContains these functions: (count=" + \
                                  str(len(self.clusters[c])) + ",size=" + \
                                  str(self.cluster_sizes[c]) +" bytes)\n")
                
                for f in sorted(self.clusters[c]):
                    clusterfile.write("\t\t" + f + " (" + \
                                      str(int(self.cmap.instr_count_map[f]["size"])) +" bytes)\n")
                clusterfile.write("\tHas privilege to access these objects: (" + \
                                  str(len(objs)) + ")\n")

                if self.obj_clusters == None:
                    for o in sorted(objs):
                        clusterfile.write("\t\t" + o + " " + self.get_obj_name(o) + "\n")
                else:
                    obj_num = 0
                    for o in sorted(objs):
                        obj_num += 1
                        if o[0] == "O" or o[0] == "P":
                            clusterfile.write("\t\t" + str(obj_num) + ". Obj cluster:" + o +"\n")
                            for oo in self.obj_cluster_map[o]:
                                clusterfile.write("\t\t\t" + oo + " " + self.get_obj_name(oo) + "\n")
                        else:
                            clusterfile.write("\t\t" + str(obj_num) + ". " + o + " " + \
                                              self.get_obj_name(o) + "\n")
                    clusterfile.write("\n")

            
        # Write out all the object clusters at the end
        clusterfile.write("Object clusters:")
        if self.obj_clusters != None:
            for o in sorted(self.obj_cluster_map):
                if len(self.obj_cluster_map) > 1:
                    clusterfile.write(o + " " + ":\n")
                    for oo in self.obj_cluster_map[o]:
                        clusterfile.write("\t" + oo + " " + self.get_obj_name(oo) + "\n")
                    clusterfile.write("\n")
                        
        #print("Average size: " + str(round(sum(sizes) / len(sizes), 3)))
        #print("Maximum size: " + str(max_size))
        #sizes = sorted(sizes, reverse=True)
        #print("Top sizes: " + str(sizes[0:10]))

# Wrapper around making a new clustering object and using it once as a possible use case.
def cluster_functions(cmap, strategy, strategy_param, pack_dead=False, extra_name=""):

    # Make sure output dir exists
    if not os.path.exists("cluster_output"):
        os.mkdir("cluster_output")
    
    clusterer = DomainCreator(cmap)

    subj_clusters = clusterer.cluster_functions(cmap, strategy, strategy_param,
                                                pack_dead, extra_name=extra_name)

    return subj_clusters


# Wrapper around making a new clustering object and using it once as a possible use case.
def cluster_functions_and_objects(cmap, strategy, strategy_param, pack_dead=False,
                                  obj_cluster_max=64, extra_name=""):

    # Make sure output dir exists
    if not os.path.exists("cluster_output"):
        os.mkdir("cluster_output")
    
    clusterer = DomainCreator(cmap)

    subj_clusters = clusterer.cluster_functions(cmap, strategy, strategy_param,
                                                pack_dead, extra_name=extra_name)

    obj_clusters = clusterer.cluster_objs(cmap, subj_clusters, obj_cluster_max,
                                          strategy, strategy_param, extra_name=extra_name)

    return (subj_clusters, obj_clusters)
    

if __name__ == '__main__':
    
    if len(sys.argv) > 2:

        # Load in CAPMAP
        cmap = CAPMAP(sys.argv[1], sys.argv[2])
        
        # Run the DomainCreator on 4 examples sizes. Inspect cluster_output afterwards to see results
        for size in [512, 1024, 2048, 4096]:
            print("Creating domains of size " + str(size) + "...")
            subj_clusters = cluster_functions(cmap, ClusterStrategy.CLUSTER_SIZE, size)

        # To cluster code and objects use:
        # (subj_clusters, obj_clusters) = cluster_functions_and_objects(cmap, ClusterStrategy.CLUSTER_SIZE, 4096, False, 64)

        # To use Ratio clustering algorithm use: 
        # (subj_clusters, obj_clusters) = cluster_functions_and_objects(cmap, ClusterStrategy.CLUSTER_RATIO, 0.000002, False, 64)
        
    else:

        print("Run with ./cluster_simple.py <vmlinux> <kmap>")
