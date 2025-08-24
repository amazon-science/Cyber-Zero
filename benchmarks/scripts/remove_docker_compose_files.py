#!/usr/bin/env python3
"""
Script to remove all docker-compose-*.yml files in the current directory and subdirectories.
"""

import os
import glob
import sys
from pathlib import Path

def find_docker_compose_files(root_dir="."):
    """
    Find all docker-compose-*.yml files recursively.
    
    Args:
        root_dir (str): Root directory to search from
        
    Returns:
        list: List of file paths matching the pattern
    """
    pattern = os.path.join(root_dir, "**/docker-compose-*.yml")
    files = glob.glob(pattern, recursive=True)
    return files

def remove_files(files, dry_run=False):
    """
    Remove the specified files.
    
    Args:
        files (list): List of file paths to remove
        dry_run (bool): If True, only print what would be removed without actually removing
    """
    removed_count = 0
    failed_count = 0
    
    for file_path in files:
        try:
            if dry_run:
                print(f"Would remove: {file_path}")
            else:
                os.remove(file_path)
                print(f"Removed: {file_path}")
            removed_count += 1
        except FileNotFoundError:
            print(f"File not found (already removed?): {file_path}")
            failed_count += 1
        except PermissionError:
            print(f"Permission denied: {file_path}")
            failed_count += 1
        except Exception as e:
            print(f"Error removing {file_path}: {e}")
            failed_count += 1
    
    return removed_count, failed_count

def main():
    """Main function to execute the removal process."""
    print("Searching for docker-compose-*.yml files...")
    
    # Find all docker-compose-*.yml files
    files = find_docker_compose_files()
    
    if not files:
        print("No docker-compose-*.yml files found.")
        return
    
    print(f"Found {len(files)} docker-compose-*.yml files:")
    for file_path in files:
        print(f"  - {file_path}")
    
    # Ask for confirmation
    response = input(f"\nDo you want to remove all {len(files)} files? (y/N): ").strip().lower()
    
    if response in ['y', 'yes']:
        print("\nRemoving files...")
        removed_count, failed_count = remove_files(files)
        
        print(f"\nSummary:")
        print(f"  Successfully removed: {removed_count}")
        print(f"  Failed to remove: {failed_count}")
        
        if failed_count > 0:
            sys.exit(1)
    else:
        print("Operation cancelled.")

if __name__ == "__main__":
    # Check if --dry-run flag is provided
    if len(sys.argv) > 1 and sys.argv[1] == "--dry-run":
        print("DRY RUN MODE - No files will be actually removed")
        print("=" * 50)
        files = find_docker_compose_files()
        if files:
            print(f"Found {len(files)} docker-compose-*.yml files that would be removed:")
            remove_files(files, dry_run=True)
        else:
            print("No docker-compose-*.yml files found.")
    else:
        main() 