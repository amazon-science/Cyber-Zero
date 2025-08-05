# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Trajectory generation module for Cyber-Zero framework.
"""

import re
import copy
import threading
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from .config import Config
from .models import ConversationTurn, TaskMeta, TrajectoryData
from .llm_client import LLMClient
from .utils import (
    load_file, shift_role, collect_trajectory, 
    save_trajectory_to_file, extract_code_blocks,
    truncate_to_first_code_block
)


class TrajectoryGenerator:
    """Main class for generating CTF solving trajectories."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.llm_client = LLMClient(config)
    
    def generate_trajectory(
        self,
        task_meta: TaskMeta,
        assistant_system_prompt: str,
        user_system_prompt: str,
        output_path: Path,
        write_lock: threading.Lock,
        verbose: bool = False
    ) -> bool:
        """
        Generate a single trajectory for a CTF task.
        
        Returns True if successful (flag submitted correctly), False otherwise.
        """
        if verbose:
            print(f"Processing task: {task_meta.task_name} ({task_meta.task_tag}) - Trajectory {task_meta.trajectory_id}")
        
        # Create initial conversation
        initial_content = self._build_initial_user_content(task_meta)
        conversation = [ConversationTurn(role="user", content=initial_content)]
        
        # Build enhanced user system prompt with task metadata
        enhanced_user_prompt = self._build_enhanced_user_prompt(
            user_system_prompt, task_meta
        )
        
        flag_turn_idx = None
        break_outer = False
        
        # Main conversation loop
        for turn_idx in range(self.config.MAX_TURNS):
            next_role = shift_role(conversation)
            
            if next_role == 'assistant':
                success, break_outer, flag_turn_idx = self._handle_assistant_turn(
                    conversation, assistant_system_prompt, task_meta.solution, 
                    turn_idx, verbose
                )
                if not success:
                    return False
            else:
                success = self._handle_user_turn(
                    conversation, enhanced_user_prompt, verbose, turn_idx
                )
                if not success:
                    return False
            
            if break_outer:
                flag_turn_idx = turn_idx
                break
        
        # Save trajectory if flag was submitted successfully
        if flag_turn_idx is not None and flag_turn_idx < self.config.MAX_TURNS:
            return self._save_successful_trajectory(
                conversation, task_meta, output_path, write_lock, verbose
            )
        else:
            if verbose:
                print(f"Flag was not submitted within max_turns for {task_meta.writeup_path} - Trajectory {task_meta.trajectory_id}")
            return False
    
    def _build_initial_user_content(self, task_meta: TaskMeta) -> str:
        """Build the initial user message content."""
        return f'''We're currently solving the following CTF challenge. The CTF challenge is a {task_meta.task_tag} problem named "{task_meta.task_name}", worth {task_meta.task_points} points. The description is:
{task_meta.task_description}
Files included in the challenge: {task_meta.task_files}

{task_meta.server_description}

INSTRUCTIONS:
Now, you're going to solve this challenge on your own. Your terminal session has started and you're in the challenge's root directory. You can use any bash commands or the special interface to help you.
Solve the challenge, executing any commands you need and writing any code that may be helpful. You can also install new software in the container using `apt-get install`, or Python packages with `pip install`.
Remember, YOU CAN ONLY ENTER ONE COMMAND AT A TIME. You should always wait for feedback after every command.
When you think you have found the flag, you can submit your solution by simply running the submit command.
Note however that you cannot use any interactive session commands (e.g. python, vim) in this environment, but you can write scripts and run them. E.g. you can write a python script and then run it with `python <script_name>.py`.

NOTE ABOUT THE EDIT COMMAND: Indentation really matters! When editing a file, make sure to insert appropriate indentation before each line!

IMPORTANT TIPS:
1. When you edit an existing file, try to minimize the changes you make to the file.

2. Please make sure that you make use of the interactive tools supplied to you! In any case, if you want to run blocking command like netcat (nc), please minimize the time by limiting its run time, for example using the "-w" flag of nc with timeout of 5 seconds - `nc -w5 127.0.0.1 80`.

3. Try to AVOID brute force attacks, but when you encounter a brute force attack, please use a script that writes output to STDOUT for the brute force instead of trying manual attempts.

4. Please DO NOT run commands in python or sage through the `-c` flag, you should create files instead.

5. Prefer using tools and commands available in the container or other tools available online over writing a lot of code or complicated commands yourself.
   In particular, prefer using `open` instead of `cat` and `search_file` instead of `grep`, and prefer using the interactive commands supplied to you!

6. DO NOT run any command that produces binary output! Instead try to use `hexdump` or `xxd`.

7. Please remember that the container is exposed to the internet, so you can use whatever online resource you would like! Use it wisely!

8. Do not use any interactive commands AT ALL! Interactive commands are only available through the commands supplied to you at the beginning - make use of them!

9. YOU CAN SOLVE THE CHALLENGES BY YOURSELF COMPLETELY - I TRUST IN YOU!

(Open file: n/a)
(Current directory: /__home__LLM_CTF_Database__{task_meta.task_name.replace(' ', '_')})
(Interactive session: n/a)
bash-$'''
    
    def _build_enhanced_user_prompt(self, base_prompt: str, task_meta: TaskMeta) -> str:
        """Build enhanced user system prompt with task metadata."""
        meta_info = {
            "task_name": task_meta.task_name,
            "task_writeup": task_meta.task_writeup,
            "flag": task_meta.solution,
            "flag_length": len(task_meta.solution),
        }
        
        enhanced_prompt = (
            base_prompt + 
            "YOU MUST UTILIZE THE FOLLOWING META INFORMATION TO SIMULATE THE CTF ENVIRONMENT WHEN THE ACTUAL CTF TASK STARTS:" +
            f"\n{meta_info}\n" +
            "YOU SHOULD USE THE META INFORMATION TO PROVIDE HINTS AND REASONS BEHIND THE HINTS TO THE PLAYER IN THE FORMAT OF `[HINT] <hint> [/HINT]`."
        )
        
        # Add detailed instructions
        enhanced_prompt += f"""

IT IS VERY COMMON THAT THE PLAYER CAN MAKE MISTAKES WHEN WRITING THE SCRIPT. YOU MUST CHECK CAREFULLY AND PROVIDE THE TRACEBACK AND CORRECT ERROR MESSAGE TO THE PLAYER.

WHEN THE PLAYER IS **GOT ERRORS MESSAGES FROM EXECUTING COMMANDS FROM THE PREVIOUS TURN** OR **CANNOT RESOLVE THE ERRORS**, YOU **MUST** PROVIDE HINTS AND REASONS BEHIND THE HINTS TO THE PLAYER IN THE FORMAT OF `[HINT] <hint> [/HINT]`.

YOU **MUST** NOT DISCLOSE ANY INFORMATION OR SUGGESTIONS UNLESS YOU USE `[HINT] <hint> [/HINT]`.
WITHOUT USING `[HINT] <hint> [/HINT]`, YOU SHOULD ONLY OUTPUT THE LINUX SYSTEM BEHAVIOR AS IF YOU ARE A REAL LINUX SYSTEM.
ANY HINTS YOU OFFER in `[HINT] <hint> [/HINT]` SHOULD BE ONLY BASED ON WHAT THE PLAYER HAS DONE SO FAR AND THE WRITEUP YOU HAVE, NOT ANYTHING BEYOND THAT.

YOU MUST MAKE SURE THE PLAYER SOLVES THE TASK BASED ON THE WRITEUP YOU HAVE. THE TASK IS WORTH `{task_meta.task_points}` POINTS, WHICH DETERMINES THE DIFFICULTY OF THE TASK.

YOU CAN ONLY DO TWO THINGS THROUGH THE WHOLE CONVERSATION: 1. EXECUTE COMMANDS WHAT THE PLAYER GIVES YOU, 2. GIVE HINTS TO THE PLAYER WHEN THE PLAYER IS STUCK.

ANY CONTEXT YOU RECEIVE IS THE BASH COMMAND.

ALWAYS RETURN THE EXECUTION RESULT OF THE COMMANDS YOU RECEIVE ALONG WITH THE META INFO of `(Open file: <path>)\\n(Current directory: <path>)\\n(Interactive session: <path>)`. ADD `(xxx more lines)` WHEN THE FILE IS OPEN AND THE FILE IS MORE THEN 100 LINES.

THE OUTPUT SHOULD BE EXACTLY THE SAME AS THE LINUX SYSTEM BEHAVIOR. DO NOT ADD ANY PLAIN TEXT DESCRIPTIONS.

HOW THE PLAYER SOLVES THE TASK IS COMPLETELY BASED ON THE WRITEUP YOU HAVE. IF THE PLAYER ATTEMPTED TO SOLVE THE TASK IN ANY OTHER WAY, YOU MUST ASSUME THE PLAYER IS WRONG AND HE/SHE CANNOT GET THE FLAG IN SUCH CASE.

YOU SHOULD HELP THE PLAYER TO IDENTIFY THE PROBLEM AND GUIDE THE PLAYER TO SOLVE THE TASK IN THE FORMAT OF `[HINT] <hint> [/HINT]` WHEN THE PLAYER IS DOING SOMETHING WRONG OR OFF THE TRACK.

THE TASK MUST NOT BE VERY STRAIGHTFORWARD AND EASY TO EXPOSE THE PATTERN TO CAPTURE THE FLAG.

PLEASE NOTE THAT THE PLAYER MAY NOT WRITE THE SCRIPT CORRECTLY. YOU MUST CHECK CAREFULLY AND PROVIDE THE TRACEBACK AND CORRECT ERROR MESSAGE TO THE PLAYER.
"""
        return enhanced_prompt
    
    def _handle_assistant_turn(
        self,
        conversation: List[ConversationTurn],
        system_prompt: str,
        expected_solution: str,
        turn_idx: int,
        verbose: bool
    ) -> Tuple[bool, bool, Optional[int]]:
        """Handle assistant turn. Returns (success, break_outer, flag_turn_idx)."""
        for retry in range(self.config.MAX_RETRIES):
            messages = self.llm_client.prepare_assistant_messages(conversation, system_prompt)
            
            # Handle hints in the last message
            if "[HINT]" in messages[-1]['content']:
                messages[-1]['content'] = messages[-1]['content'].replace(
                    "[/HINT]", 
                    "\nDO NOT MENTION 'hint' IN YOUR RESPONSE. MAKE THIS HINT AS PART OF YOUR THOUGHT PROCESS.\n[/HINT]"
                )
            
            response = self.llm_client.call_model(
                messages=messages, 
                role="assistant", 
                model_id=self.config.models.get_model_id(self.config.assistant_model_id)
            )
            
            if response is None:
                return False, False, None
            
            # Check for hint mentions
            if "[HINT]" in messages[-1]['content'] and 'hint' in response:
                continue
            
            # Truncate to first code block if multiple exist
            response = truncate_to_first_code_block(response)
            
            turn = ConversationTurn(role="assistant", content=response)
            conversation.append(turn)
            
            # Check for successful flag submission
            code_block_match = re.search(r"```bash\n([\s\S]*?)\n```", response)
            if code_block_match:
                code = code_block_match.group(1).strip()
                submit_match = re.match(r"submit\s+'([^']+)'", code)
                if submit_match and submit_match.group(1) == expected_solution:
                    return True, True, turn_idx
            
            if verbose:
                print(f"Assistant turn {turn_idx+1}.")
                print(f"\033[93m{response}\033[0m")
            
            break
        
        return True, False, None
    
    def _handle_user_turn(
        self,
        conversation: List[ConversationTurn],
        system_prompt: str,
        verbose: bool,
        turn_idx: int
    ) -> bool:
        """Handle user (terminal) turn."""
        messages = self.llm_client.prepare_user_messages(conversation, system_prompt)
        
        response = self.llm_client.call_model(
            messages=messages,
            role="user", 
            model_id=self.config.models.get_model_id(self.config.user_model_id)
        )
        
        if response is None:
            return False
        
        if verbose:
            print(f"User turn {turn_idx+1}.")
            print(f"\033[94m{response}\033[0m")
        
        turn = ConversationTurn(role="user", content=response)
        conversation.append(turn)
        
        return True
    
    def _save_successful_trajectory(
        self,
        conversation: List[ConversationTurn],
        task_meta: TaskMeta,
        output_path: Path,
        write_lock: threading.Lock,
        verbose: bool
    ) -> bool:
        """Save a successful trajectory to file."""
        trajectory = collect_trajectory(conversation, task_meta.solution, verbose)
        
        trajectory_data = TrajectoryData(
            writeup_path=task_meta.writeup_path,
            trajectory_id=task_meta.trajectory_id,
            assistant_turn_count=sum(1 for turn in trajectory if turn.role == 'assistant'),
            task_name=task_meta.task_name,
            task_tag=task_meta.task_tag,
            task_points=task_meta.task_points,
            task_description=task_meta.task_description,
            solution=task_meta.solution,
            trajectory=trajectory,
        )
        
        save_trajectory_to_file(trajectory_data.to_dict(), output_path, write_lock)
        return True 