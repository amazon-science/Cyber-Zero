# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Command-line interface for Cyber-Zero framework.
"""

import argparse
import json
import random
import time
import threading
import concurrent.futures
from pathlib import Path
from tqdm import tqdm
from typing import List, Dict, Any

from .config import Config
from .models import TaskMeta, TrajectoryData
from .trajectory_generator import TrajectoryGenerator
from .quality_evaluator import TrajectoryQualityEvaluator
from .trajectory_reformatter import TrajectoryReformatter
from .utils import (
    load_file, load_existing_combinations, split_dataset_by_part,
    load_json_file
)


class TrajectoryGenerationCLI:
    """Command-line interface for trajectory generation."""
    
    def __init__(self):
        self.config = Config()
    
    def run(self, args):
        """Main entry point for trajectory generation."""
        # Update config with temperature and top_p from args
        if hasattr(args, 'temperature') and hasattr(args, 'top_p'):
            self.config.update_model_params(
                temperature=args.temperature,
                top_p=args.top_p
            )
        
        # Update config with max_turns and max_retries from args
        if hasattr(args, 'max_turns') and hasattr(args, 'max_retries'):
            self.config.update_generation_params(
                max_turns=args.max_turns,
                max_retries=args.max_retries
            )
        
        # Update config with model IDs from args
        if hasattr(args, 'assistant_model_id') and hasattr(args, 'user_model_id'):
            self.config.update_model_ids(
                assistant_model_id=args.assistant_model_id,
                user_model_id=args.user_model_id
            )
        
        # Load system prompts
        assistant_system_prompt = load_file(self.config.ASSISTANT_PROMPT_PATH)
        user_system_prompt = load_file(self.config.USER_SYSTEM_PROMPT_PATH)
        
        # Load task metadata
        with open(args.sampled_flags_path, 'r', encoding='utf-8') as f:
            raw_objs = [json.loads(line) for line in f]
        
        # Create task objects with trajectory IDs
        task_metas = []
        for obj in raw_objs:
            for trajectory_id in range(args.trajectories_per_task):
                task_meta = TaskMeta(
                    task_name=obj.get('task_name', ''),
                    task_tag=obj.get('task_tag', ''),
                    task_points=obj.get('task_points', ''),
                    task_description=obj.get('task_description', ''),
                    solution=obj.get('solution', '').strip(),
                    task_files=obj.get('task_files', []),
                    server_description=obj.get('server_description', ''),
                    writeup_path=obj['writeup_path'],
                    task_writeup=obj.get('task_writeup'),
                    trajectory_id=trajectory_id
                )
                task_metas.append(task_meta)
        
        print(f"Loaded {len(task_metas)} tasks from {args.sampled_flags_path}")
        print(f"Will generate {args.trajectories_per_task} trajectories per task")
        
        # Split dataset by part if specified
        if hasattr(args, 'part') and args.part:
            task_metas = split_dataset_by_part(task_metas, args.part)
            print(f"Processing part {args.part}: {len(task_metas)} tasks")
        
        # Filter out existing combinations
        if not args.overwrite:
            existing_combinations = load_existing_combinations(args.output_path)
            task_metas = [
                task for task in task_metas 
                if (task.writeup_path, task.trajectory_id) not in existing_combinations
            ]
        else:
            # Clear output file if overwriting
            Path(args.output_path).write_text("")
        
        # Demo mode
        if args.demo:
            random.seed(42)
            task_metas = [random.choice(task_metas)]
            args.workers = 1
            args.verbose = True
            print(f"Demo mode: Processing 1 random task with 1 worker")
        
        print(f"Total jobs to process: {len(task_metas)}")
        
        # Generate trajectories
        self._generate_trajectories_parallel(
            task_metas, assistant_system_prompt, user_system_prompt,
            args.output_path, args.workers, args.verbose
        )
    
    def _generate_trajectories_parallel(
        self,
        task_metas: List[TaskMeta],
        assistant_system_prompt: str,
        user_system_prompt: str,
        output_path: str,
        workers: int,
        verbose: bool
    ):
        """Generate trajectories in parallel with retry logic."""
        write_lock = threading.Lock()
        remaining_tasks = task_metas.copy()
        global_retry_count = 0
        
        while remaining_tasks and global_retry_count < self.config.MAX_GLOBAL_RETRIES:
            failed_tasks = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                with tqdm(total=len(remaining_tasks), 
                         desc=f"Processing trajectories (attempt {global_retry_count + 1})") as pbar:
                    
                    # Submit all tasks
                    future_to_task = {}
                    for task_meta in remaining_tasks:
                        future = executor.submit(
                            self._generate_single_trajectory,
                            task_meta, assistant_system_prompt, user_system_prompt,
                            output_path, write_lock, verbose
                        )
                        future_to_task[future] = task_meta
                    
                    # Process results
                    for future in concurrent.futures.as_completed(future_to_task):
                        task_meta = future_to_task[future]
                        try:
                            success = future.result()
                            if not success:
                                failed_tasks.append(task_meta)
                        except Exception as e:
                            print(f"Task {task_meta.task_name} failed with exception: {e}")
                            failed_tasks.append(task_meta)
                        finally:
                            pbar.update(1)
            
            remaining_tasks = failed_tasks
            global_retry_count += 1
            
            if remaining_tasks:
                print(f"\nRetrying {len(remaining_tasks)} failed tasks (global attempt {global_retry_count + 1}/{self.config.MAX_GLOBAL_RETRIES})")
                time.sleep(5)
        
        if remaining_tasks:
            print(f"\nWarning: {len(remaining_tasks)} tasks still failed after {self.config.MAX_GLOBAL_RETRIES} global retries")
    
    def _generate_single_trajectory(
        self,
        task_meta: TaskMeta,
        assistant_system_prompt: str,
        user_system_prompt: str,
        output_path: str,
        write_lock: threading.Lock,
        verbose: bool
    ) -> bool:
        """Generate a single trajectory."""
        generator = TrajectoryGenerator(self.config)
        return generator.generate_trajectory(
            task_meta=task_meta,
            assistant_system_prompt=assistant_system_prompt,
            user_system_prompt=user_system_prompt,
            output_path=Path(output_path),
            write_lock=write_lock,
            verbose=verbose
        )


class QualityEvaluationCLI:
    """Command-line interface for quality evaluation."""
    
    def __init__(self):
        self.config = Config()
    
    def run(self, args):
        """Main entry point for quality evaluation."""
        evaluator = TrajectoryQualityEvaluator(self.config)
        write_lock = threading.Lock()
        
        # Load trajectories with robust JSON parsing
        trajectories = self._load_trajectories_safely(args.input_path)
        print(f"Loaded {len(trajectories)} trajectories from {args.input_path}")
        
        # Handle dataset splitting
        if args.part:
            trajectories = self._split_trajectories_by_part(trajectories, args.part)
            print(f"Processing part {args.part}/3: {len(trajectories)} trajectories")
        
        # Filter out existing evaluations if not overwriting
        if not args.overwrite:
            existing_evaluations = self._load_existing_evaluations(args.output_path)
            trajectories = self._filter_existing_evaluations(trajectories, existing_evaluations)
            print(f"After filtering existing evaluations: {len(trajectories)} trajectories to process")
        else:
            # Clear output file
            Path(args.output_path).write_text("")
        
        # Demo mode
        if args.demo:
            trajectories = trajectories[:1]
            args.workers = 1
            args.verbose = True
            print(f"Demo mode: Processing {len(trajectories)} trajectories with {args.workers} workers")
        
        if len(trajectories) == 0:
            print("No trajectories to process. All trajectories already evaluated or no input data.")
            return
        
        # Process trajectories in parallel
        self._evaluate_trajectories_parallel(
            trajectories, evaluator, args.model_id, args.max_retries,
            args.num_evaluations, args.output_path, args.workers,
            write_lock, args.verbose
        )
        
        # Show statistics
        self._show_quality_statistics(args.output_path)
    
    def _load_trajectories_safely(self, input_path: str) -> List[Dict[str, Any]]:
        """Load trajectories with robust JSON parsing."""
        trajectories = []
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse multi-line JSON objects
            lines = content.split('\n')
            current_json = ""
            brace_count = 0
            in_string = False
            escape_next = False
            
            for line in lines:
                if not line.strip():
                    continue
                
                current_json += line + '\n'
                
                # Track braces to detect complete JSON objects
                for char in line:
                    if escape_next:
                        escape_next = False
                        continue
                    
                    if char == '\\':
                        escape_next = True
                        continue
                        
                    if char == '"' and not escape_next:
                        in_string = not in_string
                        continue
                        
                    if not in_string:
                        if char == '{':
                            brace_count += 1
                        elif char == '}':
                            brace_count -= 1
                
                # If we have a complete JSON object
                if brace_count == 0 and current_json.strip():
                    try:
                        trajectory_obj = json.loads(current_json.strip())
                        trajectories.append(trajectory_obj)
                        current_json = ""
                    except json.JSONDecodeError:
                        print(f"Skipping invalid JSON object")
                        current_json = ""
                        brace_count = 0
                        in_string = False
                        escape_next = False
        
        except Exception as e:
            print(f"Error reading file {input_path}: {e}")
        
        return trajectories
    
    def _split_trajectories_by_part(self, trajectories: List[Dict[str, Any]], part: int) -> List[Dict[str, Any]]:
        """Split trajectories into parts."""
        total_count = len(trajectories)
        part_size = total_count // 3
        remainder = total_count % 3
        
        if part == 1:
            start_idx = 0
            end_idx = part_size + (1 if remainder > 0 else 0)
        elif part == 2:
            start_idx = part_size + (1 if remainder > 0 else 0)
            end_idx = start_idx + part_size + (1 if remainder > 1 else 0)
        else:  # part == 3
            start_idx = 2 * part_size + (2 if remainder > 1 else (1 if remainder > 0 else 0))
            end_idx = total_count
        
        return trajectories[start_idx:end_idx]
    
    def _load_existing_evaluations(self, output_path: str) -> set:
        """Load existing evaluations to avoid duplicates."""
        existing_evaluations = set()
        
        if Path(output_path).exists():
            with open(output_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                        identifier = (obj.get('writeup_path', ''), obj.get('trajectory_id', 0))
                        existing_evaluations.add(identifier)
                    except Exception:
                        continue
        
        return existing_evaluations
    
    def _filter_existing_evaluations(self, trajectories: List[Dict[str, Any]], existing_evaluations: set) -> List[Dict[str, Any]]:
        """Filter out already evaluated trajectories."""
        return [
            traj for traj in trajectories
            if (traj.get('writeup_path', ''), traj.get('trajectory_id', 0)) not in existing_evaluations
        ]
    
    def _evaluate_trajectories_parallel(
        self,
        trajectories: List[Dict[str, Any]],
        evaluator: TrajectoryQualityEvaluator,
        model_id: str,
        max_retries: int,
        num_evaluations: int,
        output_path: str,
        workers: int,
        write_lock: threading.Lock,
        verbose: bool
    ):
        """Evaluate trajectories in parallel."""
        success_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            with tqdm(total=len(trajectories), desc="Evaluating trajectory quality") as pbar:
                futures = []
                
                for trajectory_obj in trajectories:
                    future = executor.submit(
                        self._process_single_trajectory,
                        trajectory_obj, evaluator, model_id, max_retries,
                        num_evaluations, output_path, write_lock, verbose
                    )
                    futures.append(future)
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            success_count += 1
                    except Exception as e:
                        if verbose:
                            print(f"Error processing trajectory: {e}")
                    pbar.update(1)
        
        print(f"\nEvaluation completed!")
        print(f"Successfully evaluated: {success_count}/{len(trajectories)} trajectories")
        print(f"Results written to: {output_path}")
    
    def _process_single_trajectory(
        self,
        trajectory_obj: Dict[str, Any],
        evaluator: TrajectoryQualityEvaluator,
        model_id: str,
        max_retries: int,
        num_evaluations: int,
        output_path: str,
        write_lock: threading.Lock,
        verbose: bool
    ) -> bool:
        """Process a single trajectory evaluation."""
        quality_label, analysis = evaluator.evaluate_trajectory_quality(
            trajectory_obj, model_id, max_retries, num_evaluations, verbose
        )
        
        if quality_label is None:
            if verbose:
                print(f"Failed to evaluate trajectory: {trajectory_obj.get('writeup_path', 'unknown')}")
            return False
        
        # Create result object
        result = {
            'high_quality': quality_label,
            'analysis': analysis,
            **trajectory_obj  # Include all original fields
        }
        
        # Write to output file (thread-safe)
        with write_lock:
            with open(output_path, 'a', encoding='utf-8') as out:
                out.write(json.dumps(result, ensure_ascii=False) + '\n')
        
        if verbose:
            quality_str = "HIGH" if quality_label else "LOW"
            print(f"Trajectory evaluated as {quality_str} quality: {trajectory_obj.get('task_name', 'unknown')}")
        
        return True
    
    def _show_quality_statistics(self, output_path: str):
        """Show quality statistics."""
        if not Path(output_path).exists():
            return
        
        high_quality_count = 0
        total_evaluated = 0
        
        with open(output_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    total_evaluated += 1
                    if obj.get('high_quality', False):
                        high_quality_count += 1
                except Exception:
                    continue
        
        if total_evaluated > 0:
            quality_percentage = (high_quality_count / total_evaluated) * 100
            print(f"\nQuality Statistics:")
            print(f"High quality trajectories: {high_quality_count}/{total_evaluated} ({quality_percentage:.1f}%)")
            print(f"Low quality trajectories: {total_evaluated - high_quality_count}/{total_evaluated} ({100 - quality_percentage:.1f}%)")


class TrajectoryReformattingCLI:
    """Command-line interface for trajectory reformatting."""
    
    def __init__(self):
        self.config = Config()
    
    def run(self, args):
        """Main entry point for trajectory reformatting."""
        reformatter = TrajectoryReformatter(self.config)
        
        print(f"Processing trajectories from {args.input_path} to {args.output_path}...")
        
        # Load trajectories
        with open(args.input_path, 'r') as infile:
            lines = infile.readlines()
        
        # Process trajectories
        results = self._process_trajectories_parallel(lines, reformatter, args)
        
        # Apply turn count filtering if specified
        if args.turn_filter:
            print(f"Applying turn count filter: {args.turn_filter}")
            results = reformatter.filter_by_turn_count(results, args.turn_filter)
            print(f"After turn count filtering: {len(results)} trajectories remain")
        
        # Handle output
        if args.split_output:
            self._save_train_val_split(results, args, reformatter)
        else:
            self._save_single_output(results, args.output_path)
    
    def _process_trajectories_parallel(self, lines: List[str], reformatter: TrajectoryReformatter, args) -> List[str]:
        """Process trajectories in parallel."""
        total = len(lines)
        results = []
        
        # Counters for different filter types
        counters = {
            'error': 0, 'hint_filtered': 0, 'context_filtered': 0,
            'token_filtered': 0, 'low_quality_filtered': 0,
            'forbidden_ctf_filtered': 0, 'duplicates_filtered': 0
        }
        
        # Prepare arguments for multiprocessing
        process_args = [
            (line, args.enable_dedup, args.min_duplicates, args.similarity_threshold, reformatter)
            for line in lines
        ]
        
        with concurrent.futures.ProcessPoolExecutor(max_workers=args.num_workers) as executor:
            futures = [
                executor.submit(self._process_single_trajectory_reformat, arg_tuple)
                for arg_tuple in process_args
            ]
            
            for f in tqdm(concurrent.futures.as_completed(futures), total=total, desc="Processing"):
                try:
                    result_type, result_data = f.result()
                    if result_type == "success":
                        results.append(result_data)
                    else:
                        # Count different filter types
                        filter_type = result_type.replace('filtered_', '').replace('_filtered', '')
                        if filter_type in counters:
                            counters[filter_type] += 1
                        else:
                            counters['error'] += 1
                except Exception:
                    counters['error'] += 1
        
        # Print statistics
        print(f"Successfully processed {len(results)} trajectories")
        for filter_type, count in counters.items():
            if count > 0:
                print(f"Filtered out {count} trajectories: {filter_type}")
        
        return results
    
    def _process_single_trajectory_reformat(self, args_tuple) -> tuple:
        """Process a single trajectory for reformatting."""
        line, enable_dedup, min_duplicates, similarity_threshold, reformatter = args_tuple
        
        try:
            traj = json.loads(line)
            
            # Check for low quality
            if 'high_quality' in traj and traj['high_quality'] is False:
                return ("filtered_low_quality", None)
            
            # Check for forbidden CTFs
            writeup_path = traj.get('writeup_path', '')
            if any(ctf_name in writeup_path for ctf_name in reformatter.FORBIDDEN_CTFS):
                return ("filtered_forbidden_ctf", None)
            
            # Reformat trajectory
            updated_traj = reformatter.reformat_trajectory(traj)
            if updated_traj is None:
                return ("filtered_reformat", None)
            
            # Check for unwanted markers
            if reformatter.contains_unwanted_markers(updated_traj):
                return ("filtered_hint", None)
            
            # Check token length
            token_count = reformatter.check_token_length(updated_traj)
            if token_count > reformatter.config.TOKEN_LIMIT:
                return ("filtered_token", None)
            
            # Check for duplicates if enabled
            if enable_dedup and reformatter.has_excessive_duplicates(
                updated_traj, min_duplicates, similarity_threshold
            ):
                return ("filtered_duplicates", None)
            
            return ("success", json.dumps(updated_traj))
            
        except Exception:
            return ("error", None)
    
    def _save_train_val_split(self, results: List[str], args, reformatter: TrajectoryReformatter):
        """Save results as train/validation split."""
        # Prioritize trajectories with scroll_down
        results = reformatter.prioritize_scroll_down(results)
        
        # Split
        random.seed(42)
        split_idx = int(len(results) * args.split)
        train_results = results[:split_idx]
        val_results = results[split_idx:]
        
        # Determine output paths
        output_path = Path(args.output_path)
        if args.turn_filter:
            stem = output_path.stem + f"_{args.turn_filter}"
            suffix = output_path.suffix
            base_path = output_path.parent / f"{stem}{suffix}"
        else:
            base_path = output_path
        
        train_path = str(base_path) + ".train.jsonl"
        val_path = str(base_path) + ".val.jsonl"
        
        # Write files
        with open(train_path, 'w') as train_file:
            for item in train_results:
                train_file.write(item + '\n')
        
        with open(val_path, 'w') as val_file:
            for item in val_results:
                val_file.write(item + '\n')
        
        print(f"Train set: {len(train_results)} written to {train_path}")
        print(f"Validation set: {len(val_results)} written to {val_path}")
    
    def _save_single_output(self, results: List[str], output_path: str):
        """Save results to a single output file."""
        with open(output_path, 'w') as outfile:
            for item in results:
                outfile.write(item + '\n')
        print(f"Output written to {output_path}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Cyber-Zero CTF Trajectory Framework")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Trajectory generation command
    gen_parser = subparsers.add_parser('generate', help='Generate CTF trajectories')
    gen_parser.add_argument('--sampled_flags_path', required=True, 
                           help='Input JSONL file with task metadata')
    gen_parser.add_argument('--output_path', required=True,
                           help='Output JSONL file for trajectories')
    gen_parser.add_argument('--trajectories_per_task', type=int, default=1,
                           help='Number of trajectories per task')
    gen_parser.add_argument('--workers', type=int, default=16,
                           help='Number of parallel workers')
    gen_parser.add_argument('--overwrite', action='store_true',
                           help='Overwrite existing output file')
    gen_parser.add_argument('--verbose', action='store_true',
                           help='Verbose output')
    gen_parser.add_argument('--demo', action='store_true',
                           help='Demo mode with single task')
    gen_parser.add_argument('--part', type=int, choices=[1, 2, 3],
                           help='Process specific part of dataset')
    gen_parser.add_argument('--temperature', type=float, default=0.6,
                           help='Temperature for trajectory generation')
    gen_parser.add_argument('--top_p', type=float, default=0.95,
                           help='Top-p for trajectory generation')
    gen_parser.add_argument('--max_turns', type=int, default=60,
                           help='Maximum turns for trajectory generation')
    gen_parser.add_argument('--max_retries', type=int, default=5,
                           help='Maximum retries for trajectory generation')
    gen_parser.add_argument('--assistant_model_id', type=str, default='deepseek-v3-0324',
                           help='Model ID for the assistant')
    gen_parser.add_argument('--user_model_id', type=str, default='deepseek-v3-0324',
                           help='Model ID for the user')
    
    # Quality evaluation command
    eval_parser = subparsers.add_parser('evaluate', help='Evaluate trajectory quality')
    eval_parser.add_argument('--input_path', required=True,
                            help='Input JSONL file with trajectories to evaluate')
    eval_parser.add_argument('--output_path', required=True,
                            help='Output JSONL file with quality labels')
    eval_parser.add_argument('--model_id', default='sonnet35v2',
                            help='Model for quality evaluation')
    eval_parser.add_argument('--workers', type=int, default=128,
                            help='Number of parallel workers')
    eval_parser.add_argument('--max_retries', type=int, default=3,
                            help='Max retries per evaluation')
    eval_parser.add_argument('--num_evaluations', type=int, default=1,
                            help='Number of evaluation queries per trajectory')
    eval_parser.add_argument('--overwrite', action='store_true',
                            help='Overwrite output file and re-evaluate all trajectories')
    eval_parser.add_argument('--verbose', action='store_true',
                            help='Print verbose evaluation messages')
    eval_parser.add_argument('--demo', action='store_true',
                            help='Process only a few samples for demonstration')
    eval_parser.add_argument('--part', type=int, choices=[1, 2, 3],
                            help='Process only 1/3 of the data. Choose part 1, 2, or 3')
    
    # Trajectory reformatting command
    reformat_parser = subparsers.add_parser('reformat', help='Reformat trajectories for training')
    reformat_parser.add_argument('--input_path', required=True,
                                help='Input trajectory JSONL file')
    reformat_parser.add_argument('--output_path', required=True,
                                help='Output reformatted JSONL file')
    reformat_parser.add_argument('--num_workers', type=int, default=32,
                                help='Number of parallel workers to use')
    reformat_parser.add_argument('--split', type=float, default=0.9,
                                help='Fraction of data to use for training (default: 0.9)')
    reformat_parser.add_argument('--split_output', action='store_true',
                                help='Output train/val splits as separate files')
    reformat_parser.add_argument('--turn_filter', choices=['uniform', 'less_than_40', 'above_40'],
                                default=None, help='Filter trajectories based on turn count')
    reformat_parser.add_argument('--min_duplicates', type=int, default=3,
                                help='Filter out trajectories with >= this many duplicate turns')
    reformat_parser.add_argument('--similarity_threshold', type=float, default=0.9,
                                help='Word overlap similarity threshold for duplicate detection')
    reformat_parser.add_argument('--enable_dedup', action='store_true',
                                help='Enable deduplication')
    
    args = parser.parse_args()
    
    if args.command == 'generate':
        cli = TrajectoryGenerationCLI()
        cli.run(args)
    elif args.command == 'evaluate':
        cli = QualityEvaluationCLI()
        cli.run(args)
    elif args.command == 'reformat':
        cli = TrajectoryReformattingCLI()
        cli.run(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main() 