# μSCOPE: A Methodology for Analyzing Least-Privilege Compartmentalization in Large Software Artifacts

Welcome. Please find information related to our project on automated analysis on large software artifacts.

Link to the [Paper](https://fierce-lab.gitlab.io/uscope/uscope_raid21.pdf)

<!-- Trigger our visits counter by visiting countapi -->
<script async src="https://api.countapi.xyz/hit/fierce-lab.gitlab.io/uscope-repo"></script>

## Organization of the Site
```
.
├── README.md                        This document.
├── analysis                         μSCOPE analysis code
├── compartment-explorer             Linux kernel compartment explorer.
├── css 
├── index.html                       μSCOPE landing page
├── object-explorer                  Linux kernel object explorer.
├── run.sh                           Script to run uscope analysis.
├── uscope_raid21.pdf                Full paper for μSCOPE

```

## Analysis Code

μSCOPE's compartment-generation and analysis code can be found in the [analysis directory](https://gitlab.com/fierce-lab/uscope/-/tree/master/analysis).

To get started, follow the [μSCOPE analysis tutorial](analysis/tutorial/README.md)

## Abstract

By prioritizing simplicity and portability, least-privilege engineering has been an afterthought in OS design, resulting in monolithic kernels where any exploit leads to total compromise. μSCOPE (“microscope”) addresses this problem by automatically identifying opportunities for least-privilege separation. μSCOPE replaces expert-driven, semi-automated analysis with a general methodology for exploring a continuum of security vs. performance design points by adopting a quantitative and systematic approach to privilege analysis. In the paper, we detail how we applied the μSCOPE methodology to the Linux kernel, allowing us to accomplish the following:

The instrumentation of the entire Linux kernel, granting comprehensive, fine-grained memory access and call activity
The mapping of fine-grained memory accesses and calls to semantic information
The reporting of a separability analysis on the kernel, using both quantitative privilege and overhead metrics
We discover opportunities for orders of magnitude privilege reduction while predicting relatively low overheads - at 15% mediation overhead, overprivilege in Linux can be reduced up to 99.8% - suggesting fine-grained privilege separation is feasible and laying the groundwork for accelerating real privilege separation.

## Data Exploration

We collected a significant amount of data as well as present a few ways to explore compartmentalizations.

[μSCOPE Linux Object Explorer](https://fierce-lab.gitlab.io/uscope/object-explorer/): shows access trace for select set of objects with links to code.

[μSCOPE Linux Compartment Explorer](https://fierce-lab.gitlab.io/uscope/compartment-explorer/): shows compartmentalization results from µSCOPE algorithms.

[μSCOPE Visualizations](https://fierce-lab.gitlab.io/memorizer/dashboard/index.html): profiling visualizations to understand what's happening in Linux.

[μSCOPE Directory Based Communication Heatmap](https://fierce-lab.gitlab.io/memorizer/dashboard/heatmap.html): heatmap showing interactions between directory based compartmentalization in Linux.

[Who's using the most privilege in Linux?](https://fierce-lab.gitlab.io/memorizer/dashboard/sunburst.html): sunburst showing components with highest access degree.

[Who's allocating the most data in Linux?](https://fierce-lab.gitlab.io/memorizer/dashboard/alloc.html): flame graphs showing who's allocating the most in Linux.

## Raw data

The raw data collected for μSCOPE can be downloaded here: [RAID2021.tar.gz](https://drive.google.com/file/d/1ms7bQvJiUUpq5LpBIeQQZJXZVpNrLMFS).

Warning: the tar file is 2.7GB and unpacks into about 16GB of data.

This data is collected from 8 CPU-months of Linux kernel workload traces on the [Memorizer kernel](https://fierce-lab.gitlab.io/memorizer/).

## Bibtex

```
@inproceedings{Roessler:USCOPE:2021,
  title = {{{$\mu$SCOPE}}: {{A Methodology}} for {{Analyzing Least}}-{{Privilege Compartmentalization}} in {{Large Software Artifacts}}},
  booktitle = {In 24th {{International Symposium}} on {{Research}} in {{Attacks}}, {{Intrusions}} and {{Defenses}} ({{RAID}} '21)},
  author = {Roessler, Nick and Atayde, Lucas and Palmer, Imani and McKee, Derrick and Pandey, Jai and Kemerlis, Vasileios P and Payer, Mathias and Bates, Adam and DeHon, Andr{\'e} and Smith, Jonathan M and Dautenhahn, Nathan},
  year = {2021},
  pages = {16},
  publisher = {{ACM}}
}
```
