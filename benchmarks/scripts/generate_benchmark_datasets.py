#!/usr/bin/env python3

import os
import json
from pathlib import Path

def find_challenge_files(base_dir):
    """Find all challenge.json files in a directory tree."""
    challenge_files = []
    for root, dirs, files in os.walk(base_dir):
        if "challenge.json" in files:
            challenge_files.append(os.path.join(root, "challenge.json"))
    return sorted(challenge_files)

def read_challenge_info(challenge_path):
    """Read challenge.json and extract basic info."""
    try:
        with open(challenge_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading {challenge_path}: {e}")
        return {}

def generate_intercode_ctf_dataset():
    """Generate dataset for intercode_ctf benchmark."""
    base_dir = "intercode_ctf"
    challenge_files = find_challenge_files(base_dir)
    
    dataset = {}
    
    for challenge_file in challenge_files:
        # Parse path: intercode_ctf/category/number/challenge.json
        path_parts = Path(challenge_file).parts
        if len(path_parts) >= 4:
            category = path_parts[1]  # forensics, misc, etc.
            challenge_number = path_parts[2]  # number
            
            # Read challenge info
            challenge_info = read_challenge_info(challenge_file)
            challenge_name = challenge_info.get('name', f'Challenge #{challenge_number}')
            
            # Create key in format: ic-category-number
            key = f"ic-{category}-{challenge_number}"
            
            # Get the directory path (excluding challenge.json)
            challenge_dir = str(Path(challenge_file).parent)
            
            dataset[key] = {
                "benchmark": "intercode_ctf",
                "category": category,
                "challenge": challenge_name,
                "challenge_id": challenge_number,
                "path": challenge_dir
            }
    
    return dataset

def generate_cybench_dataset():
    """Generate dataset for cybench benchmark."""
    base_dir = "cybench"
    challenge_files = find_challenge_files(base_dir)
    
    dataset = {}
    
    for challenge_file in challenge_files:
        # Parse path: cybench/event/category/challenge_name/challenge.json
        path_parts = Path(challenge_file).parts
        if len(path_parts) >= 5:
            event = path_parts[1]  # S23, GLA, HTB, etc.
            category = path_parts[2]  # forensics, misc, crypto, etc.
            challenge_name = path_parts[3]  # challenge name
            
            # Read challenge info
            challenge_info = read_challenge_info(challenge_file)
            
            # Get actual challenge name from JSON if available
            actual_name = challenge_info.get('name', challenge_name)
            
            # Create key in format: cb-event-category-challenge_name
            safe_challenge_name = challenge_name.replace(' ', '_').replace('[', '').replace(']', '').lower()
            key = f"cb-{event.lower()}-{category}-{safe_challenge_name}"
            
            # Get the directory path (excluding challenge.json)
            challenge_dir = str(Path(challenge_file).parent)
            
            dataset[key] = {
                "benchmark": "cybench",
                "event": event,
                "category": category,
                "challenge": actual_name,
                "path": challenge_dir
            }
    
    return dataset

def main():
    print("Generating intercode_ctf dataset...")
    intercode_dataset = generate_intercode_ctf_dataset()
    
    print("Generating cybench dataset...")
    cybench_dataset = generate_cybench_dataset()
    
    # Write intercode_ctf dataset
    with open('intercode_ctf.json', 'w', encoding='utf-8') as f:
        json.dump(intercode_dataset, f, indent=2, ensure_ascii=False)
    
    # Write cybench dataset
    with open('cybench.json', 'w', encoding='utf-8') as f:
        json.dump(cybench_dataset, f, indent=2, ensure_ascii=False)
    
    print(f"Generated intercode_ctf.json with {len(intercode_dataset)} challenges")
    print(f"Generated cybench.json with {len(cybench_dataset)} challenges")
    
    # Print some sample entries
    print("\nSample intercode_ctf entries:")
    for i, (key, value) in enumerate(intercode_dataset.items()):
        if i < 3:
            print(f"  {key}: {value}")
    
    print("\nSample cybench entries:")
    for i, (key, value) in enumerate(cybench_dataset.items()):
        if i < 3:
            print(f"  {key}: {value}")

if __name__ == "__main__":
    main() 