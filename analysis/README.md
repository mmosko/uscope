# Analysis

The analysis directory contains various scripts for analyzing privilege graphs (CAPMAPs).

Get started by following [the tutorial](tutorial/README.md) on using this analysis code.

### CAPMAP.py

The CAPMAP class is the core representation of a privilege graph. CAPMAP.py reads a .cmap file and constructs an in-memory representation of the graph amenable to analysis using the NetworkX graph library. Additionally, it uses `objdump` and `nm` on the `vmlinux`binary to extract information for interpereting the cmap, such as the symbol names and function sizes. 

Usage:
```python
from CAPMAP import *
cmap = CAPMAP(path_to_vmlinux, path_to_cmap)
# cmap object now redy for analysis
```

### DomainCreator.py

This class contains the algorithmic domain creation algorithms that treat compartment generation as an optimization problem over the privilege-performance space. See uSCOPE paper sections 6.1 and 6.2 

Code domain are maps from function to domainID and object domains are maps from object to domainID.

The DomainCreator can be run standalone on default settings with:

```python DomainCreator.py <vmlinux> <kmap_file>```

Or may be configured:
```python
from CAPMAP import *
from DomainCreator import *
cmap = CAPMAP(path_to_vmlinux, path_to_cmap)
# Create code clusters of size 2048 bytes maximum
subj_domains = cluster_functions(cmap, ClusterStrategy.CLUSTER_SIZE, 2048)
```

The DomainCreator additionally writes the created domains to `cluster_output` for inspection.

### calculate_PS.py

This script calculates the Privilege Set (PS) for a given CAPMAP.
See uSCOPE paper 5.3.1.

When run standalone, the script generates a PS table for a given cmap file using some default (syntactic) domains: ```python calculate_PS.py <vmlinux> <kmap_file>```

Alternativley, it an be used to return PS data from a CAPMAP and a particular set of subject domains, object domains, and an assignment of mediated/unmediated to each edge:
```python
cmap = CAPMAP(path_to_vmlinux, path_to_cmap)
PS = calculate_PS_cluster_linkmap(cmap, subj_domains, obj_domains, edge_assignment)
```

The subject domains and object domains may be created by the DomainCreator or may be selected from a range of built-in domains, such as `cmap.func_to_dir` (the directory domains). See example at bottom of file.

### calculate_overhead.py
This script defines the cost profiles for a range of possible compartmentalization enforcement mechanisms, and then estimates the cost of enforcement on a given CMAP and a set of subject domains, object domains, and edge assignments. 

```python
cmap = CAPMAP(path_to_vmlinux, path_to_cmap)
overhead = calculate_overhead(cmap, subj_domains, obj_domains, edge_assignment)
```

Note that CAPMAP.py looks for a `.baseline` file when it loads a CAPMAP, which should contain the baseline cycle count for that traced workload. For overhead estimates, make sure to provide a baseline cycle count. See example at bottom of file.

### sweep_edge_assignment.py
This script traces out the range of privilege/performance design points that can be reached for a given CAPMAP and domains by iteratively setting all the edge types from mediated to unmediated. This allows one to visualize the privilege/performance tradeoff space. See uSCOPE paper 6.4.

Execution: ```python calculate_edge_assignment.py <vmlinux> <kmap_file>```
Result: `edge_assignment_results/edge_assignment_curves.txt` contains the range of privilege/performance design points.

See example at bottom of file.