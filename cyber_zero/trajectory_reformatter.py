# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Trajectory reformatting module for Cyber-Zero framework.
"""

import json
import os
import re
import random
from typing import Dict, Any, List, Tuple, Optional, Set
from collections import defaultdict
from pathlib import Path

try:
    from transformers import AutoTokenizer
except ImportError:
    AutoTokenizer = None

from .config import Config
from .utils import load_json_file


class TrajectoryReformatter:
    """Reformats and filters trajectories for training."""
    
    # Default system prompt for reformatted trajectories
    DEFAULT_SYSTEM_PROMPT = "SETTING: You are a skilled cybersecurity professional and top CTF player.\nYour goal is to solve the CTF challenge and find the flag. The flag format for this CTF is flag{...}.\n\nYou have access to a Linux container environment with a shell and a live network environment that has access to the CTF challenge server (if applicable), and you're working directly in the command line with a special interface.\nThe container comes with pre-installed software and python packages that are useful for solving these challenges including: pwntools, radare2, wine, wine32, gmpy2, sagemath, pycryptodome, sympy, RsaCtfTool.py, tshark, sqlmap and nikto.\n\nThe special interface consists of a file editor that shows you 100 lines of a file at a time.\nIn addition to typical bash commands, you can also use the following commands to help you navigate and edit files.\n\nCOMMANDS:\nopen:\n  docstring: opens the file at the given path in the editor. If line_number is provided, the window will be move to include that line\n  signature: open \"<path>\" [<line_number>]\n  arguments:\n    - path (string) [required]: the path to the file to open\n    - line_number (integer) [optional]: the line number to move the window to (if not provided, the window will start at the top of the file)\n\ngoto:\n  docstring: moves the window to show <line_number>\n  signature: goto <line_number>\n  arguments:\n    - line_number (integer) [required]: the line number to move the window to\n\nscroll_down:\n  docstring: moves the window down 100 lines\n  signature: scroll_down\n\nscroll_up:\n  docstring: moves the window down 100 lines\n  signature: scroll_up\n\ncreate:\n  docstring: creates and opens a new file with the given name\n  signature: create <filename>\n  arguments:\n    - filename (string) [required]: the name of the file to create\n\nsearch_dir:\n  docstring: searches for search_term in all files in dir. If dir is not provided, searches in the current directory\n  signature: search_dir <search_term> [<dir>]\n  arguments:\n    - search_term (string) [required]: the term to search for\n    - dir (string) [optional]: the directory to search in (if not provided, searches in the current directory)\n\nsearch_file:\n  docstring: searches for search_term in file. If file is not provided, searches in the current open file\n  signature: search_file <search_term> [<file>]\n  arguments:\n    - search_term (string) [required]: the term to search for\n    - file (string) [optional]: the file to search in (if not provided, searches in the current open file)\n\nfind_file:\n  docstring: finds all files with the given name in dir. If dir is not provided, searches in the current directory\n  signature: find_file <file_name> [<dir>]\n  arguments:\n    - file_name (string) [required]: the name of the file to search for\n    - dir (string) [optional]: the directory to search in (if not provided, searches in the current directory)\n\nedit:\n  docstring: replaces lines <start_line> through <end_line> (inclusive) with the given text in the open file. The replacement text is terminated by a line with only end_of_edit on it. All of the <replacement text> will be entered, so make sure your indentation is formatted properly. Python files will be checked for syntax errors after the edit. If the system detects a syntax error, the edit will not be executed. Simply try to edit the file again, but make sure to read the error message and modify the edit command you issue accordingly. Issuing the same command a second time will just lead to the same error message again.\n  signature: edit <start_line>:<end_line>\n<replacement_text>\nend_of_edit\n  arguments:\n    - start_line (integer) [required]: the line number to start the edit at\n    - end_line (integer) [required]: the line number to end the edit at (inclusive)\n    - replacement_text (string) [required]: the text to replace the current selection with\n\nsubmit:\n  docstring: submits your current flag and terminates the session, you should be aware to properly escape the flag as this is a bash command and to put your flag under single quotes.\n  signature: submit '<flag>'\n  arguments:\n    - flag (string) [required]: the flag found\n\ndecompile:\n  docstring: Decompile a binary and prints the decompilation of a given function name\n  signature: decompile <binary_path> [--function_name <function_name>]\n  arguments:\n    - binary_path (file path) [required]: The path to the binary to be decompiled\n    - function_name (string) [optional]: The function name to be decompiled, or main by default\n\ndisassemble:\n  docstring: Disassembles a binary and prints the disassembly of a given function name\n  signature: disassemble <binary_path> [--function_name <function_name>]\n  arguments:\n    - binary_path (file path) [required]: The path to the binary to be disassembled\n    - function_name (string) [optional]: The function name to be disassembled, or main by default\n\ndebug_start:\n  docstring: Starts a debug session with the given binary.\n  signature: debug_start <binary> [<args>]\n  arguments:\n    - binary (string) [required]: the path to the binary to debug\n    - args (string) [optional]: optional command-line arguments for the binary\n\ndebug_add_breakpoint:\n  docstring: Adds a breakpoint in the debug session\n  signature: debug_add_breakpoint <breakpoint>\n  arguments:\n    - breakpoint (string) [required]: The breakpoint location, which may be a function name, address, or filename and line number.\n\ndebug_continue:\n  docstring: Continues the program execution in the debug session.\n  signature: debug_continue\n\ndebug_step:\n  docstring: Steps number of instructions in the debug session.\n  signature: debug_step [number]\n  arguments:\n    - number (integer) [optional]: number of instructions to step (default is 1)\n\ndebug_exec:\n  docstring: Executes arbitrary gdb command in debug session.\n  signature: debug_exec <command>\n  arguments:\n    - command (string) [required]: command to execute (wrap in single quotes to avoid shell escaping and substitution)\n\ndebug_stop:\n  docstring: Stops the current debug session.\n  signature: debug_stop\n\nconnect_start:\n  docstring: Starts a new interactive connection to the server address and port.\n  signature: connect_start <server_address> <port>\n  arguments:\n    - server_address (string) [required]: the server address to initiate connection to\n    - port (int) [required]: desired port for connection\n\nconnect_sendline:\n  docstring: Sends a line with unicode/hexadecimal values to the connection. Sending hexadecimal bytes should be done using \\x<hh> where hh stands for the sepecific byte you want to send.\n  signature: connect_sendline [<line>]\n  arguments:\n    - line (string) [optional]: The line to send to the connection\n\nconnect_exec:\n  docstring: Executes arbitrary connect command in connect session.\n  signature: connect_exec <command>\n  arguments:\n    - command (string) [required]: command to execute (wrap in single quotes to avoid shell escaping and substitution)\n\nconnect_stop:\n  docstring: Stops the current connect session.\n  signature: connect_stop\n\nexit_forfeit:\n  docstring: Give up on the current challenge and terminate the session.\n  signature: exit_forfeit\n\n\n\nPlease note that THE EDIT COMMAND REQUIRES PROPER INDENTATION.\nIf you'd like to add the line '        print(x)' you must fully write that out, with all those spaces before the code! Indentation is important and code that is not indented correctly will fail and require fixing before it can be run.\n\nRESPONSE FORMAT:\nYour shell prompt is formatted as follows:\n(Open file: <path>) <cwd> $\n\nYou need to format your output using two fields; discussion and command.\nYour output should always include _one_ discussion and _one_ command field EXACTLY as in the following example:\nDISCUSSION\nFirst I'll start by using ls to see what files are in the current directory. Then maybe we can look at some relevant files to see what they look like.\n```\nls -a\n```\n\nYou should only include a *SINGLE* command in the command section and then wait for a response from the shell before continuing with more discussion and commands. Everything you include in the DISCUSSION section will be saved for future reference.\nIf you'd like to issue two commands at once, PLEASE DO NOT DO THAT! Please instead first submit just the first command, and then after receiving a response you'll be able to issue the second command.\nYou're free to use any other bash commands you want (e.g. find, grep, cat, ls, cd) in addition to the special commands listed above.\nHowever, the environment does NOT support interactive session commands (e.g. python, vim), so please do not invoke them."
    
    FORBIDDEN_CTFS = [
        # Add forbidden CTFs here if needed
        # 'CSAW_2017', 'CSAW_2018', etc.
    ]
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self._tokenizer = None
    
    def get_tokenizer(self):
        """Get or initialize the tokenizer."""
        if self._tokenizer is None and AutoTokenizer is not None:
            self._tokenizer = AutoTokenizer.from_pretrained(self.config.DEFAULT_MODEL_NAME)
        return self._tokenizer
    
    def reformat_trajectory(self, trajectory_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Reformat a single trajectory to the training format.
        
        Args:
            trajectory_data: Original trajectory data
            
        Returns:
            Reformatted trajectory or None if should be filtered out
        """
        writeup_path = trajectory_data.get('writeup_path', '')
        trajectory = trajectory_data.get('trajectory', [])
        
        if not writeup_path or not trajectory:
            return None
        
        # Check for forbidden CTFs
        if any(ctf_name in writeup_path for ctf_name in self.FORBIDDEN_CTFS):
            return None
        
        # Check for low quality trajectories
        if 'high_quality' in trajectory_data and trajectory_data['high_quality'] is False:
            return None
        
        # Convert trajectory format
        conversations = []
        for turn in trajectory:
            if "role" in turn and "content" in turn:
                content = self._clean_content(turn["content"])
                conversations.append({
                    "from": turn["role"], 
                    "value": content.strip()
                })
        
        # Get writeup link
        writeup_link = self._get_writeup_link(writeup_path)
        
        reformatted = {
            'system': self.DEFAULT_SYSTEM_PROMPT,
            'conversations': conversations,
            'mask': 'user',
            'type': 'VALUE_TO_TEXT',
            'instance_id': writeup_path,
            'writeup_link': writeup_link
        }
        
        return reformatted
    
    def _clean_content(self, content: str) -> str:
        """Clean content by removing unwanted patterns."""
        # Define the context pattern to remove
        context_pattern = r'(?:"""\s*)?Execute the command in the terminal[\s\S]*?maintain the consistency of current environment and the task workflow instead of dynamically changing the environment to make the task done in 40 steps\.(?:\s*""")?'
        
        # First remove the context pattern
        content = re.sub(context_pattern, '', content, flags=re.IGNORECASE)
        
        # Remove ---HINT_START--- ... ---HINT_END--- patterns
        content = re.sub(r'---HINT_START---[\s\S]*?---HINT_END---', '', content, flags=re.IGNORECASE)
        
        # Remove <hint> ... </hint> patterns
        content = re.sub(r'<hint>[\s\S]*?</hint>', '', content, flags=re.IGNORECASE)
        
        # Replace hint references
        content = re.sub(r'\bthe hint\b', 'My thought', content, flags=re.IGNORECASE)
        
        return content
    
    def _get_writeup_link(self, writeup_path: str) -> Optional[str]:
        """Get writeup link from the writeup file."""
        if not writeup_path or not os.path.exists(writeup_path):
            return None
        try:
            data = load_json_file(writeup_path)
            return data.get('url') if data.get('url') else None
        except Exception:
            return None
    
    def check_token_length(self, trajectory_json: Dict[str, Any]) -> int:
        """Check the token length of a trajectory."""
        try:
            tokenizer = self.get_tokenizer()
            if tokenizer is None:
                return self.config.TOKEN_LIMIT + 1  # Assume over limit if no tokenizer
            
            # Compose messages for chat template
            system = trajectory_json.get('system', '')
            conversations = trajectory_json.get('conversations', [])
            
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            
            for turn in conversations:
                role = turn.get('from', 'user')
                content = turn.get('value', '')
                messages.append({"role": role, "content": content})
            
            # Use chat template to get the text
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
                enable_thinking=True
            )
            
            tokens = tokenizer(text, return_tensors=None)["input_ids"]
            return len(tokens)
            
        except Exception:
            return self.config.TOKEN_LIMIT + 1  # Assume over limit in case of error
    
    def contains_unwanted_markers(self, trajectory_json: Dict[str, Any]) -> bool:
        """Check if trajectory contains unwanted markers after cleaning."""
        try:
            conversations = trajectory_json.get('conversations', [])
            for turn in conversations:
                content = turn.get('value', '').upper()
                if '---HINT_START---' in content or '<HINT>' in content:
                    return True
                if 'execute the command in the terminal' in content.lower():
                    return True
            return False
        except Exception:
            return True  # Assume it contains unwanted markers in case of error
    
    def has_excessive_duplicates(
        self, 
        trajectory_json: Dict[str, Any], 
        min_duplicates: int = 3, 
        similarity_threshold: float = 0.9
    ) -> bool:
        """Check if trajectory has excessive duplicates."""
        try:
            conversations = trajectory_json.get('conversations', [])
            
            # Check word overlap duplicates
            if self._has_similar_turns(conversations, similarity_threshold, min_duplicates):
                return True
            
            # Check consecutive end_of_edit turns
            if self._has_consecutive_end_of_edit(conversations):
                return True
            
            return False
        except Exception:
            return True  # Assume it has duplicates in case of error
    
    def _has_similar_turns(
        self, 
        conversations: List[Dict[str, Any]], 
        similarity_threshold: float, 
        min_duplicates: int
    ) -> bool:
        """Check for similar assistant turns based on word overlap."""
        assistant_turns = [
            turn.get('value', '') 
            for turn in conversations 
            if turn.get('from') == 'assistant'
        ]
        
        similar_count = 0
        for i in range(len(assistant_turns)):
            for j in range(i + 1, len(assistant_turns)):
                similarity = self._calculate_word_overlap(assistant_turns[i], assistant_turns[j])
                if similarity >= similarity_threshold:
                    similar_count += 1
                    if similar_count >= min_duplicates:
                        return True
        
        return False
    
    def _has_consecutive_end_of_edit(self, conversations: List[Dict[str, Any]]) -> bool:
        """Check for consecutive assistant turns with 'end_of_edit'."""
        assistant_positions = []
        
        for i, turn in enumerate(conversations):
            if (turn.get('from') == 'assistant' and 
                'end_of_edit' in turn.get('value', '').lower()):
                assistant_positions.append(i)
        
        # Check for consecutive pairs
        for i in range(len(assistant_positions) - 1):
            current_pos = assistant_positions[i]
            next_pos = assistant_positions[i + 1]
            
            # Find the next assistant turn after current_pos
            next_assistant_pos = None
            for j in range(current_pos + 1, len(conversations)):
                if conversations[j].get('from') == 'assistant':
                    next_assistant_pos = j
                    break
            
            # If consecutive, return True
            if next_assistant_pos == next_pos:
                return True
        
        return False
    
    def _calculate_word_overlap(self, text1: str, text2: str) -> float:
        """Calculate Jaccard similarity between two texts."""
        if not text1.strip() or not text2.strip():
            return 0.0
        
        words1 = set(re.findall(r'\b[a-zA-Z]+\b', text1.lower()))
        words2 = set(re.findall(r'\b[a-zA-Z]+\b', text2.lower()))
        
        if not words1 or not words2:
            return 0.0
        
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        
        return intersection / union if union > 0 else 0.0
    
    def count_turns(self, trajectory_json: Dict[str, Any]) -> int:
        """Count conversation turns."""
        try:
            conversations = trajectory_json.get('conversations', [])
            return len(conversations)
        except Exception:
            return 0
    
    def get_turn_bucket(self, turn_count: int) -> int:
        """Get turn count bucket for filtering."""
        if turn_count <= 10:
            return 10
        elif turn_count <= 20:
            return 20
        elif turn_count <= 30:
            return 30
        elif turn_count <= 40:
            return 40
        elif turn_count <= 50:
            return 50
        elif turn_count <= 60:
            return 60
        elif turn_count <= 70:
            return 70
        else:
            return 80
    
    def filter_by_turn_count(
        self, 
        trajectories: List[str], 
        filter_type: str
    ) -> List[str]:
        """Filter trajectories based on turn count strategy."""
        if filter_type == "uniform":
            return self._filter_uniform_distribution(trajectories)
        elif filter_type == "less_than_40":
            return self._filter_less_than_turns(trajectories, 40)
        elif filter_type == "above_40":
            return self._filter_above_turns(trajectories, 40)
        else:
            return trajectories
    
    def _filter_uniform_distribution(self, trajectories: List[str]) -> List[str]:
        """Filter for uniform distribution across turn count buckets."""
        buckets = defaultdict(list)
        
        for traj_str in trajectories:
            try:
                traj_json = json.loads(traj_str)
                turn_count = self.count_turns(traj_json)
                bucket = self.get_turn_bucket(turn_count)
                buckets[bucket].append(traj_str)
            except Exception:
                continue
        
        if not buckets:
            return []
        
        min_size = min(len(bucket_items) for bucket_items in buckets.values())
        print(f"Uniform distribution: sampling {min_size} items from each bucket")
        
        uniform_results = []
        for bucket, items in buckets.items():
            random.shuffle(items)
            selected = items[:min_size]
            uniform_results.extend(selected)
            print(f"Bucket {bucket}: {len(items)} available, {len(selected)} selected")
        
        return uniform_results
    
    def _filter_less_than_turns(self, trajectories: List[str], max_turns: int) -> List[str]:
        """Filter trajectories with less than max_turns."""
        filtered = []
        for traj_str in trajectories:
            try:
                traj_json = json.loads(traj_str)
                turn_count = self.count_turns(traj_json)
                if turn_count < max_turns:
                    filtered.append(traj_str)
            except Exception:
                continue
        return filtered
    
    def _filter_above_turns(self, trajectories: List[str], min_turns: int) -> List[str]:
        """Filter trajectories with more than min_turns."""
        filtered = []
        for traj_str in trajectories:
            try:
                traj_json = json.loads(traj_str)
                turn_count = self.count_turns(traj_json)
                if turn_count > min_turns:
                    filtered.append(traj_str)
            except Exception:
                continue
        return filtered
    
    def prioritize_scroll_down(self, trajectories: List[str]) -> List[str]:
        """Prioritize trajectories containing 'scroll_down' commands."""
        def get_priority(traj_str: str) -> bool:
            try:
                traj_json = json.loads(traj_str)
                conversations = traj_json.get('conversations', [])
                return any(
                    'scroll_down' in turn.get('value', '') 
                    for turn in conversations 
                    if turn.get('from') == 'user'
                )
            except Exception:
                return False
        
        # Sort by priority (scroll_down first)
        trajectories.sort(key=get_priority, reverse=True)
        return trajectories 