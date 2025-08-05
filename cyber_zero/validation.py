# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Validation functions for Cyber-Zero framework.
"""

import re
from typing import List

from .config import Config


class ResponseValidator:
    """Validates responses and commands according to Cyber-Zero rules."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
    
    def check_markdown_balance(self, content: str, role: str) -> bool:
        """Check if markdown content has balanced code blocks."""
        if role == "assistant":
            return content.count("```bash") == 1
        else:
            return content.count("```") == 0
    
    def check_hint_format(self, content: str) -> bool:
        """Check if hint tags are properly formatted."""
        hint_tag_start_count = content.count("[HINT]")
        hint_tag_end_count = content.count("[/HINT]")
        
        if hint_tag_start_count == 0 and hint_tag_end_count == 0:
            return True
        elif hint_tag_start_count == 1 and hint_tag_end_count == 1:
            hint_tag_start_idx = content.find("[HINT]")
            hint_tag_end_idx = content.find("[/HINT]")
            return hint_tag_start_idx < hint_tag_end_idx
        else:
            return False
    
    def check_colon_patterns(self, content: str, role: str) -> bool:
        """Check for required colon patterns in user responses."""
        for pattern in self.config.validation.COLON_PATTERNS:
            expected_count = 1 if role == "user" else 0
            actual_count = content.count(pattern)
            if actual_count != expected_count:
                return False
        return True
    
    def validate_action(self, content: str, action_type: str) -> bool:
        """Validate specific action types in the content."""
        # Common patterns
        redirect_pipe_pattern = r'(?:\s*(?:>+|>>)\s*(?:"[^"]+"|\'[^\']+\'|\S+)|\s*\|\s*\S+(?:\s+\S+)*)*'
        quoted_arg = r'(?:"[^"]+"|\'[^\']+\'|\S+)'
        multiline_content = r'(?:[^\n]|\n(?!end_of_content))*'
        
        # Validate action count
        first_word = content.split()[0] if content.split() else ""
        action_count = sum(1 for action in self.config.validation.ACTION_TYPES 
                          if action == first_word)
        if action_count != 1:
            return False
        
        # Action-specific validation
        if action_type == "edit":
            pattern = r'^edit\s+(\d+):(\d+)\n(.*?)\nend_of_edit$'
            match = re.match(pattern, content, re.DOTALL)
            if not match:
                return False
            start, end = int(match.group(1)), int(match.group(2))
            return start <= end and start > 0
        
        elif action_type == "open":
            pattern = r'^open\s+' + quoted_arg + r'(?:\s+\d+)?$'
            return bool(re.match(pattern, content))
        
        elif action_type == "goto":
            pattern = r'^goto\s+\d+$'
            return bool(re.match(pattern, content))
        
        elif action_type in ["scroll_down", "scroll_up", "debug_continue", "debug_stop", "connect_stop"]:
            return content.strip() == action_type
        
        elif action_type == "create":
            pattern = r'^create\s+' + quoted_arg + r'$'
            return bool(re.match(pattern, content))
        
        elif action_type in ["search_dir", "search_file", "find_file"]:
            pattern = r'^' + action_type + r'\s+' + quoted_arg + r'(?:\s+' + quoted_arg + r')?' + redirect_pipe_pattern + r'$'
            return bool(re.match(pattern, content))
        
        elif action_type == "submit":
            pattern = r'^submit\s+(?:\'[^\']+\'|"[^"]+"|\S+)$'
            return bool(re.match(pattern, content))
        
        elif action_type in ["decompile", "disassemble"]:
            pattern = r'^' + action_type + r'\s+' + quoted_arg + r'(?:\s+--function_name\s+' + quoted_arg + r')?' + redirect_pipe_pattern + r'$'
            return bool(re.match(pattern, content))
        
        elif action_type == "debug_start":
            pattern = r'^debug_start\s+' + quoted_arg + r'(?:\s+' + quoted_arg + r')?$'
            return bool(re.match(pattern, content))
        
        elif action_type == "debug_add_breakpoint":
            pattern = r'^debug_add_breakpoint\s+' + quoted_arg + r'$'
            return bool(re.match(pattern, content))
        
        elif action_type == "debug_step":
            pattern = r'^debug_step(?:\s+\d+)?$'
            return bool(re.match(pattern, content))
        
        elif action_type == "debug_exec":
            pattern = r'^debug_exec\s+(?:\'[^\']+\'|"[^"]+")$'
            return bool(re.match(pattern, content))
        
        elif action_type == "connect_start":
            pattern = r'^connect_start\s+' + quoted_arg + r'\s+\d+$'
            return bool(re.match(pattern, content))
        
        elif action_type == "connect_sendline":
            pattern = r'^connect_sendline\s+' + multiline_content + r'$'
            return bool(re.match(pattern, content, re.DOTALL))
        
        elif action_type == "connect_exec":
            pattern = r'^connect_exec\s+(?:\'(?:[^\'\\]|\\.)*\'|"(?:[^"\\]|\\.)*")$'
            return bool(re.match(pattern, content, re.DOTALL))
        
        return False
    
    def validate_response(self, content: str, role: str) -> bool:
        """Validate the overall response format and content."""
        if role == "assistant":
            # Extract code blocks - must be exactly one
            code_blocks = re.findall(r"```bash\n([\s\S]*?)\n```", content)
            if len(code_blocks) != 1:
                print(f"Code block not found or multiple blocks")
                return False
            
            code = code_blocks[0].strip()
            if not code:  # Empty command
                return False
            
            # Check for invalid standalone operators
            invalid_endings = ['|', '>', '>>', '2>', '2>>', '<']
            if any(code.endswith(ending) for ending in invalid_endings):
                print(f"Invalid standalone operator: {code}")
                return False
            
            # Check for dangling operators
            if re.search(r'[|>]\s*$', code):
                print(f"Dangling operator")
                return False
            
            return self._validate_command_chain(code)
        
        return True
    
    def _validate_command_chain(self, code: str) -> bool:
        """Validate a chain of commands connected by && or ||."""
        # Handle edit commands by replacing their newlines temporarily
        edit_commands = re.findall(r'(edit\s+\d+:\d+\n.*?\nend_of_edit)', code, re.DOTALL)
        temp_code = code
        
        for i, edit_cmd in enumerate(edit_commands):
            temp_code = temp_code.replace(edit_cmd, f'EDIT_PLACEHOLDER_{i}')
        
        # Split by chain operators
        chain_parts = re.split(r'(\s*(?:&&|\|\|)\s*)', temp_code)
        
        # Check if chain is properly formed
        if (chain_parts[0].strip() == '' or 
            (len(chain_parts) > 1 and chain_parts[-1].strip() == '')):
            return False
        
        # Validate each command in the chain
        for i in range(0, len(chain_parts), 2):  # Commands are at even indices
            command = chain_parts[i].strip()
            if not command:
                return False
            
            # Replace back edit placeholders
            for j, edit_cmd in enumerate(edit_commands):
                if f'EDIT_PLACEHOLDER_{j}' in command:
                    command = command.replace(f'EDIT_PLACEHOLDER_{j}', edit_cmd)
            
            if not self._validate_single_command(command):
                return False
        
        # Check for proper chain structure
        if len(chain_parts) % 2 == 0:
            return False
        
        return True
    
    def _validate_single_command(self, command: str) -> bool:
        """Validate a single command."""
        command_parts = command.split()
        if not command_parts:
            return False
        
        command_type = command_parts[0]
        
        # Reject unknown actions
        if command_type.startswith("unknown_"):
            return False
        
        # Check if it's a known action
        used_actions = [action for action in self.config.validation.ACTION_TYPES 
                       if action == command_type]
        
        if len(used_actions) > 1:
            return False
        
        # If it's a known action, validate it
        if used_actions:
            action_type = used_actions[0]
            
            # Check for missing required arguments
            no_arg_actions = ["scroll_down", "scroll_up", "debug_continue", 
                            "debug_stop", "connect_stop", "debug_step"]
            if len(command_parts) < 2 and action_type not in no_arg_actions:
                return False
            
            return self.validate_action(command, action_type)
        
        # For non-action commands (regular bash), check basic structure
        if all(c in ['|', '>', '<', '&'] for c in command.strip()):
            return False
        
        return True 