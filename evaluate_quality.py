# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env python3

#
"""
Refactored quality evaluation script for Cyber-Zero framework.

This script maintains backward compatibility with the original evaluate_quality.py
while using the new modular architecture.
"""

import argparse
import sys
from pathlib import Path

# Add the current directory to Python path to import cyber_zero
sys.path.insert(0, str(Path(__file__).parent))

from cyber_zero.cli import QualityEvaluationCLI


def main():
    """Main entry point maintaining original CLI interface."""
    parser = argparse.ArgumentParser(description="Evaluate CTF trajectory quality using LLM.")
    parser.add_argument('--input_path', 
                       default='merged_trajectories_final_contaminated.jsonl', 
                       help='Input JSONL file with trajectories to evaluate.')
    parser.add_argument('--output_path', 
                       default='trajectories_final_quality_evaluated.jsonl', 
                       help='Output JSONL file with quality labels.')
    parser.add_argument('--model_id', 
                       default='sonnet35v2', 
                       help='Model ID for quality evaluation.')
    parser.add_argument('--workers', 
                       type=int, default=128, 
                       help='Number of parallel workers.')
    parser.add_argument('--max_retries', 
                       type=int, default=3, 
                       help='Max retries per evaluation.')
    parser.add_argument('--num_evaluations', 
                       type=int, default=1, 
                       help='Number of evaluation queries per trajectory. If any returns false, trajectory is considered low quality.')
    parser.add_argument('--overwrite', 
                       action='store_true', 
                       help='Overwrite output file and re-evaluate all trajectories.')
    parser.add_argument('--verbose', 
                       action='store_true', 
                       help='Print verbose evaluation messages.')
    parser.add_argument('--demo', 
                       action='store_true', 
                       help='Process only a few samples for demonstration.')
    parser.add_argument('--part', 
                       type=int, choices=[1, 2, 3], 
                       help='Process only 1/3 of the data. Choose part 1, 2, or 3.')
    
    args = parser.parse_args()
    
    # Create CLI instance and run
    cli = QualityEvaluationCLI()
    cli.run(args)


if __name__ == "__main__":
    main() 