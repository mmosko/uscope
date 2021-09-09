#!/usr/bin/python

# Calculate the external call ratio (ECR) for a given cut.

from CAPMAP import *
import sys


# Calculate the EAR for a cmap and a cut. Returns a dict indexed by op
def calculate_ECR(cmap, cut):
    
    internal_accesses = 0
    external_accesses = 0
            
    for node in cmap.dg:

        if cmap.get_node_type(node) == NodeType.OBJECT:
            continue
        
        src_ip = cmap.get_node_ip(node)
        src_func = cmap.ip_to_func[src_ip]
        src_comp = cut[src_func]
                        
        for obj_node in cmap.dg.successors(node):

            if cmap.get_node_type(obj_node) == NodeType.OBJECT:
                continue

            dest_ip = cmap.get_node_ip(obj_node)
            dest_func = cmap.ip_to_func[dest_ip]
            dest_comp = cut[dest_func]
            edge = cmap.dg.get_edge_data(node, obj_node)

            if src_comp == dest_comp:
                internal_accesses += edge["call"]
            else:
                external_accesses += edge["call"]

    if internal_accesses + external_accesses == 0:
        raise Exception("Error: tried to calculate ECR for cmap with no call data")
    ECR = round(float(external_accesses) / (internal_accesses + external_accesses), 5)
    return ECR

if __name__ == '__main__':
    if len(sys.argv) > 2:
        cmap = CAPMAP(sys.argv[1], sys.argv[2])
        print("Topdir ECR: " + str(calculate_ECR(cmap, cmap.func_to_topdir)))
        print("Dir ECR: " + str(calculate_ECR(cmap, cmap.func_to_dir)))
        print("File ECR: " + str(calculate_ECR(cmap, cmap.func_to_file)))
        print("Function ECR: " + str(calculate_ECR(cmap, cmap.func_to_func)))
    else:
        print("python calculate_ECR.py <vmlinux> <kmap>")
