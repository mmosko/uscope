#!/bin/bash

# This script pull down the uscop docker image
# and run the analysis code using the RAID2021
# data or the cmap file provided by the user.

BASEDIR=`pwd`
USCOPE_RESULT_DIR=$BASEDIR/uscope_result

# Check software dependency
check_dependency()
{
    if [ ! dpkg -s docker >/dev/null 2>&1 ]
    then
        echo "docker not installed..."
        exit 0
    fi  
}

# run uscope analysis code
run_uscope()
{
    local uscope_dir="/home/uscope"
    local analysis_dir="$uscope_dir/analysis"
    local RAID_dir="$uscope_dir/RAID2021"
    local cluster_dir="$analysis_dir/cluster_output"
    local edge_dir="$analysis_dir/edge_assignment_results"
    local pdf_dir="$analysis_dir/output"

    if [ ! -d $USCOPE_RESULT_DIR ]
    then
        mkdir $USCOPE_RESULT_DIR
    fi

    if [ ! -d $BASEDIR/RAID2021 ]
    then
        echo "Download RAID2021 data..."
        docker run --name tmp_uscope brucechien/memorizer:uscope /bin/true > /dev/null 2>&1
        docker cp tmp_uscope:/home/uscope/RAID2021 $BASEDIR > /dev/null 2>&1
        docker rm tmp_uscope > /dev/null 2>&1
        echo "Download complete and output to $BASEDIR/RAID2021"
        echo ""
    fi

    echo "Run uscope analysis:"
    echo "1) Creating compartments"
    echo "2) Exploring the continuum"
    echo "3) Shell mode"
    read option
    echo ""
    
    case $option in
        "1")
            # Run DomainCreator and output result to host
            read -p "Input the vmlinux file to run analysis: " vmlinux
            read -p "Input the cmap file to run analysis: " cmap_file
            echo ""
            
            # Run sweep_edge_assignment and output result to host
            base_vmlinux=$(basename $vmlinux)
            base_cmap=$(basename $cmap_file)

            echo "Running compartment..."
            docker run --name tmp_compartment -td brucechien/memorizer:uscope > /dev/null 2>&1
            docker cp $vmlinux tmp_compartment:$analysis_dir/$base_vmlinux
            docker cp $cmap_file tmp_compartment:$analysis_dir/$base_cmap
            docker exec tmp_compartment python $analysis_dir/DomainCreator.py $analysis_dir/$base_vmlinux $analysis_dir/$base_cmap
            docker cp -a tmp_compartment:$cluster_dir  $USCOPE_RESULT_DIR/compartment
            echo "Output compartment result to $USCOPE_RESULT_DIR/compartment"
            echo ""
            
            docker stop tmp_compartment > /dev/null 2>&1
            docker rm tmp_compartment > /dev/null 2>&1
            ;;
        "2")
            read -p "Input the vmlinux file to run analysis: " vmlinux
            read -p "Input the cmap file to run analysis: " cmap_file
            echo ""
            
            # Run sweep_edge_assignment and output result to host
            base_vmlinux=$(basename $vmlinux)
            base_cmap=$(basename $cmap_file)

            echo "Running continum..."
            docker run --name tmp_continum -td brucechien/memorizer:uscope > /dev/null 2>&1
            docker cp $vmlinux tmp_continum:$analysis_dir/$base_vmlinux
            docker cp $cmap_file tmp_continum:$analysis_dir/$base_cmap
            docker exec tmp_continum python $analysis_dir/sweep_edge_assignment.py $analysis_dir/$base_vmlinux $analysis_dir/$base_cmap
            docker cp -a tmp_continum:$edge_dir  $USCOPE_RESULT_DIR/continum
            echo "Output continum result to $USCOPE_RESULT_DIR/continum"
            echo ""
            
            # Copy the pdf plot to host
            docker cp -a tmp_continum:$pdf_dir  $USCOPE_RESULT_DIR/continum
            echo "Output continum pdf graph to $USCOPE_RESULT_DIR/continum"
            echo ""
            docker stop tmp_continum > /dev/null 2>&1
            docker rm tmp_continum > /dev/null 2>&1
            ;;
        "3")
            docker run -it brucechien/memorizer:uscope bash
            ;;
        *)
            echo "Please enter valid number"
            exit 0
            ;;
    esac
}

prompt_mode()
{
    check_dependency

    echo "################################"
    echo "## Welcome to µSCOPE Shell ##"
    echo "################################"
    echo ""
    echo "Run uscope to analyze data..."
    echo ""
    run_uscope
}

prompt_mode
