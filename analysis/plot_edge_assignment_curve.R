#!/usr/bin/Rscript
## This R script plots the output of sweep_edge_assignment.py

## Libraries and settings
library(ggplot2)
library(reshape2)
library(scales)
options(scipen=1)

## Read in data and label columns
data = read.table("edge_assignment_results/edge_assignment_curves.txt")
colnames(data) <- c("Mechanism", "Cut", "Num_Unmediated", "Overhead", "PS", "PSR")

## Throw away all columns except those labeled 6
data = data[,(colnames(data) %in% c("Mechanism", "Cut", "Num_Unmediated", "Overhead", "PS", "PSR"))]

## Preview the loaded data
head(data)

## Cut out mechanisms besides pagetable_ept for plotting
data_cuts = data
data_cuts = subset(data_cuts, Mechanism == "pagetable_ept")

## Calculate number of cuts we're plotting and make enough colors
num_cuts=length(unique(data_cuts$Cut))
colors=rainbow(num_cuts)

## Create pdf file in output dir. Make output dir if it does not exist
dir.create("output", showWarnings=FALSE)
pdf("output/edge_assignment_compare_cuts.pdf", height=1.74, width=8.5)

## Function for pretty printing axis labels
xAxisLabelFunc <- function(x) sprintf("%.5f", x)
point <- format_format(big.mark = ",", decimal.mark = ".", scientific = FALSE)

## Print Overhead vs PS plot
ggplot(data=data_cuts, aes(x=PSR, y=Overhead)) +
    geom_line(aes(colour=Cut)) +
    scale_y_log10(breaks=c(1e-1, 1e0,1e1,1e2,1e3,1e4,1e5), labels=point, limits=c(.1,20000)) +
    scale_x_log10(breaks=trans_breaks("log10", function(x) 10^x), labels=xAxisLabelFunc, limits=c(0.000030, 0.3)) +
    theme(legend.position="right", legend.key.size=unit(.50, "cm"), legend.text=element_text(size=8), legend.title=element_text(size=10)) +
    xlab("PSR") + ylab("Kernel Overhead(%)") +
    scale_color_manual(values=colors, name="Separation Hypothesis") +
    guides(color=guide_legend(ncol=2)) +
    theme(plot.margin = unit(c(.02,.02,.02,.02), "cm"))
