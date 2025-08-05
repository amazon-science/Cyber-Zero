# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env python3

#
"""
Refactored trajectory generation script for Cyber-Zero framework.

This script maintains backward compatibility with the original generate_trajectory.py
while using the new modular architecture.
"""

import argparse
import sys
from pathlib import Path

# Add the current directory to Python path to import cyber_zero
sys.path.insert(0, str(Path(__file__).parent))

from cyber_zero.cli import TrajectoryGenerationCLI


def main():
    """Main entry point maintaining original CLI interface."""
    parser = argparse.ArgumentParser(description="Simulate CTF LLM trajectories in parallel, turn-by-turn.")
    parser.add_argument('--sampled_flags_path', 
                       default='task_meta_writeups.jsonl', 
                       help='Input JSONL file with task meta.')
    parser.add_argument('--output_path', 
                       default='trajectories.jsonl', 
                       help='Output JSONL file for trajectories.')
    parser.add_argument('--assistant_model_id', 
                       default='deepseek-v3-0324', 
                       help='Model ID for the assistant LLM.')
    parser.add_argument('--user_model_id', 
                       default='deepseek-v3-0324', 
                       help='Model ID for the user (terminal) LLM.')
    parser.add_argument('--max_turns', 
                       type=int, default=60, 
                       help='Maximum number of turns (bash + player) to simulate.')
    parser.add_argument('--workers', 
                       type=int, default=16, 
                       help='Number of parallel workers.')
    parser.add_argument('--max_retries', 
                       type=int, default=5, 
                       help='Max retries per item.')
    parser.add_argument('--trajectories_per_task', 
                       type=int, default=3, 
                       help='Number of trajectories to generate per task.')
    parser.add_argument('--overwrite', 
                       action='store_true', 
                       help='Overwrite output file and regenerate all trajectories.')
    parser.add_argument('--verbose', 
                       action='store_true', 
                       help='Print verbose error/info messages.')
    parser.add_argument('--part', 
                       type=int, choices=[1, 2, 3], default=1, 
                       help='Process part 1, 2, or 3 of the dataset (splits dataset into 3 equal parts).')
    parser.add_argument('--temperature', 
                       type=float, default=0.6, 
                       help='Temperature for model generation (default: 0.6).')
    parser.add_argument('--top_p', 
                       type=float, default=0.95, 
                       help='Top-p (nucleus sampling) parameter for model generation (default: 0.95).')
    parser.add_argument('--demo', 
                       action='store_true', 
                       help='Process only one random sample with one worker for demonstration.')
    
    args = parser.parse_args()

    # Print configuration being used
    print(f"Using model parameters:")
    print(f"  Assistant model: {args.assistant_model_id}")
    print(f"  User model: {args.user_model_id}")
    print(f"  Temperature: {args.temperature}")
    print(f"  Top-p: {args.top_p}")
    print(f"  Max turns: {args.max_turns}")
    print(f"  Max retries: {args.max_retries}")
    
    # Create CLI instance and run
    cli = TrajectoryGenerationCLI()
    cli.run(args)


if __name__ == "__main__":
    main() 