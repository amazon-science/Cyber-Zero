# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env python3

#
"""
Refactored trajectory reformatting script for Cyber-Zero framework.

This script maintains backward compatibility with the original reformat_trajectories.py
while using the new modular architecture.
"""

import argparse
import sys
from pathlib import Path

# Add the current directory to Python path to import cyber_zero
sys.path.insert(0, str(Path(__file__).parent))

from cyber_zero.cli import TrajectoryReformattingCLI


def main():
    """Main entry point maintaining original CLI interface."""
    parser = argparse.ArgumentParser(description="Process and reformat trajectories.")
    parser.add_argument('--input_path', 
                       default='trajectories_final_quality_evaluated.jsonl', 
                       help='Input trajectory JSONL file.')
    parser.add_argument('--output_path', 
                       default='refined_trajectories_final.jsonl', 
                       help='Output reformatted JSONL file.')
    parser.add_argument('--num_workers', 
                       type=int, default=32, 
                       help='Number of parallel workers to use.')
    parser.add_argument('--split', 
                       type=float, default=0.9, 
                       help='Fraction of data to use for training (default: 0.9).')
    parser.add_argument('--split_output', 
                       action='store_true', 
                       help='If set, output train/val splits as <output_path>.train.jsonl and <output_path>.val.jsonl')
    parser.add_argument('--turn_filter', 
                       choices=['uniform', 'less_than_40', 'above_40'], 
                       default=None, 
                       help='Filter trajectories based on turn count: uniform (samples uniformly distributed across turn buckets 10,20,30,40,50,60,70,80), less_than_40 (only keep samples with <40 turns), above_40 (only keep samples with >40 turns)')
    parser.add_argument('--min_duplicates', 
                       type=int, default=3,
                       help='Filter out trajectories with >= this many duplicate assistant turns (0 disables duplicate filtering, default: 3)')
    parser.add_argument('--similarity_threshold', 
                       type=float, default=0.9,
                       help='Word overlap similarity threshold for duplicate detection (0.0-1.0, default: 0.9)')
    parser.add_argument('--enable_dedup', 
                       action='store_true', 
                       help='Enable deduplication')
    
    args = parser.parse_args()
    
    # Validate duplicate filtering arguments
    if args.enable_dedup:
        if not (0.0 <= args.similarity_threshold <= 1.0):
            print("Error: Similarity threshold must be between 0.0 and 1.0")
            sys.exit(1)
        print(f"Duplicate filtering enabled: >= {args.min_duplicates} duplicates, similarity threshold: {args.similarity_threshold}")
    
    # Create CLI instance and run
    cli = TrajectoryReformattingCLI()
    cli.run(args)


if __name__ == "__main__":
    main()