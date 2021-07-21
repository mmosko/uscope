
# μSCOPE: A Methodology for Analyzing Least-Privilege Compartmentalization in Large Software Artifacts

Welcome. Please find information related to our project on automated analysis on large software artifacts.

Link to the [Paper](https://fierce-lab.gitlab.io/uscope/uscope_raid21.pdf)

# Organization of the Site

TBD

# Analysis Code

TBD

# Abstract

By prioritizing simplicity and portability, least-privilege engineering has been an afterthought in OS design, resulting in monolithic kernels where any exploit leads to total compromise. μSCOPE (“microscope”) addresses this problem by automatically identifying opportunities for least-privilege separation. μSCOPE replaces expert-driven, semi-automated analysis with a general methodology for exploring a continuum of security vs. performance design points by adopting a quantitative and systematic approach to privilege analysis. In the paper, we detail how we applied the μSCOPE methodology to the Linux kernel, allowing us to accomplish the following:

The instrumentation of the entire Linux kernel, granting comprehensive, fine-grained memory access and call activity
The mapping of fine-grained memory accesses and calls to semantic information
The reporting of a separability analysis on the kernel, using both quantitative privilege and overhead metrics
We discover opportunities for orders of magnitude privilege reduction while predicting relatively low overheads - at 15% mediation overhead, overprivilege in Linux can be reduced up to 99.8% - suggesting fine-grained privilege separation is feasible and laying the groundwork for accelerating real privilege separation.

# Analysis Tools

We collected a significant amount of data as well as present a few ways to explore compartmentalizations.

μSCOPE Linux Object Explorer: [Object Explorer](https://uscope-linux.github.io/object_explorer/)
μSCOPE Linux Compartment Explorer: [Compartment Explorer](https://uscope-linux.github.io/compartment_explorer/)

# Bibtex

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
