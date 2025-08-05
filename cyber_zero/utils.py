# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Common utility functions for Cyber-Zero framework.
"""

import json
import re
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import threading

from .models import ConversationTurn
from .config import Config


def load_file(path: Union[str, Path]) -> str:
    """Load text content from a file."""
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def load_json_file(path: Union[str, Path]) -> Dict[str, Any]:
    """Load JSON content from a file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_writeup_content(writeup_path: Union[str, Path]) -> str:
    """Load writeup markdown content from a JSON file."""
    data = load_json_file(writeup_path)
    return data.get("markdown", "")


def extract_code_blocks(text: str) -> Optional[str]:
    """Extract the last bash code block from markdown text."""
    code_block = re.search(r"```bash\n([\s\S]*?)\n```", text)
    if code_block:
        return code_block.group(1).strip()
    return None


def shift_role(conversation: List[ConversationTurn]) -> str:
    """
    Determine the next role to generate in the conversation.
    Assumes conversation alternates and starts with 'user'.
    """
    if not conversation:
        return 'user'
    
    last_role = conversation[-1].role
    return 'assistant' if last_role == 'user' else 'user'


def collect_trajectory(
    conversation: List[ConversationTurn], 
    expected_solution: str, 
    verbose: bool = False
) -> List[ConversationTurn]:
    """
    Collect trajectory stopping when assistant submits the correct flag.
    """
    trajectory = []
    
    for turn in conversation:
        trajectory.append(turn)
        
        if (turn.role == 'assistant' and 
            'submit' in turn.content):
            
            # Check if this submit command contains the expected solution
            m = re.search(r"submit\s+'([^']+)'", turn.content)
            if (m and expected_solution in m.group(1)) or (expected_solution in turn.content):
                break
                
            if verbose:
                print(f"Submit command does not contain expected solution '{expected_solution}' in '{turn.content}'")
    
    return trajectory


def save_trajectory_to_file(
    trajectory_data: Dict[str, Any], 
    output_path: Union[str, Path], 
    write_lock: threading.Lock
) -> None:
    """Safely write trajectory data to output file."""
    with write_lock:
        with open(output_path, 'a', encoding='utf-8') as out:
            out.write(json.dumps(trajectory_data, ensure_ascii=False) + '\n')


def load_existing_combinations(output_path: Union[str, Path]) -> List[tuple]:
    """Load existing trajectory combinations to avoid duplicates."""
    existing_combinations = []
    
    if Path(output_path).exists():
        with open(output_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if obj.get('solution', '') == '':
                        continue
                    if 'writeup_path' in obj:
                        existing_combinations.append((
                            obj['writeup_path'], 
                            obj.get('trajectory_id', 0)
                        ))
                except Exception:
                    continue
                    
    return existing_combinations


def split_dataset_by_part(objs: List[Any], part: int) -> List[Any]:
    """Split dataset into three equal parts and return the specified part."""
    if part not in [1, 2, 3]:
        raise ValueError("Part must be 1, 2, or 3")
    
    total_objs = len(objs)
    part_size = total_objs // 3
    
    if part == 1:
        return objs[:part_size]
    elif part == 2:
        return objs[part_size:2*part_size]
    else:  # part == 3
        return objs[2*part_size:]


def retry_with_exponential_backoff(
    func, 
    max_retries: int = 5, 
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0
):
    """
    Execute a function with exponential backoff retry logic.
    """
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            
            delay = min(base_delay * (backoff_factor ** attempt), max_delay)
            time.sleep(delay)
    
    return None


def clean_response_content(content: str) -> str:
    """Clean response content by removing specific patterns."""
    # Remove hint patterns while preserving the rest
    cleaned = re.sub(r'\[HINT\][\s\S]*?\[/HINT\]', '', content, flags=re.IGNORECASE)
    return cleaned.strip()


def truncate_to_first_code_block(response: str) -> str:
    """
    Truncate response to include only content up to the first code block.
    This ensures consistent behavior when multiple code blocks exist.
    """
    code_block_match = re.search(r"```bash\n([\s\S]*?)\n```", response)
    
    if code_block_match:
        # Count total code blocks
        all_code_blocks = re.findall(r"```bash\n[\s\S]*?\n```", response)
        if len(all_code_blocks) > 1:
            # Truncate response to end after the first code block
            response = response[:code_block_match.end()]
    
    return response 