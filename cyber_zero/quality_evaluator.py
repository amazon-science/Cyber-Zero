# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Quality evaluation module for Cyber-Zero framework.
"""

import json
import re
import os
from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path

from .config import Config
from .llm_client import LLMClient
from .utils import load_writeup_content


class TrajectoryQualityEvaluator:
    """Evaluates the quality of CTF solving trajectories."""
    
    QUALITY_EVALUATION_PROMPT = """You are an expert and strict CTF security researcher and educator. Your task is to evaluate the quality of a CTF solving trajectory.

You will be given:
1. A CTF task with its description, writeup, and expected solution
2. A conversation trajectory showing how an AI agent solved the task step by step

Please evaluate whether this trajectory demonstrates HIGH QUALITY by checking if it aligns with:
1. **Task Writeup Alignment**: Does the trajectory workflow match the intended approach described in the writeup? If the writeup does not provide useful information, you should judge based on your own knowledge and experience.
2. **Real-world CTF Practice**: Does the solving approach follow realistic CTF methodologies and best practices?

NOT HIGH QUALITY indicators:
- Deviates the method and scenario from writeup solution
- Uses unrealistic or impossible techniques
- Shows inconsistent or illogical progression
- Execution behavior of Linux system has flaws
- Relies on lucky guesses without proper analysis
- Contains errors in technical understanding
- Has unclear or confusing methodology
- Not be able to use as the learning material for the intermediate level CTF players
- The approach cannot generalize to other CTF tasks

Think step by step in plain text and then respond with a Markdown code block (``` and ```) ONLY containing "true" if the trajectory demonstrates VERY HIGH QUALITY, or "false" if it does not meet the very high quality standards."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.llm_client = LLMClient(config)
    
    def evaluate_trajectory_quality(
        self,
        trajectory_obj: Dict[str, Any],
        model_id: str = "sonnet35v2",
        max_retries: int = 3,
        num_evaluations: int = 1,
        verbose: bool = False
    ) -> Tuple[Optional[bool], Optional[str]]:
        """
        Evaluate a single trajectory for quality using the specified model.
        
        Args:
            trajectory_obj: Trajectory data dictionary
            model_id: Model to use for evaluation
            max_retries: Maximum retries per evaluation
            num_evaluations: Number of evaluation queries to perform
            verbose: Print detailed logs
            
        Returns:
            Tuple of (quality_label, analysis_response)
            - quality_label: True for high quality, False for low quality, None for evaluation failure
            - analysis_response: The last response from the model
        """
        
        # Extract trajectory information
        task_name = trajectory_obj.get('task_name', '')
        task_tag = trajectory_obj.get('task_tag', '')
        task_points = trajectory_obj.get('task_points', '')
        task_description = trajectory_obj.get('task_description', '')
        solution = trajectory_obj.get('solution', '')
        trajectory = trajectory_obj.get('trajectory', [])
        writeup_path = trajectory_obj.get('writeup_path', '')
        
        if verbose:
            print(f"Evaluating trajectory for: {task_name} ({task_tag}) - {task_points} points")
            print(f"Will perform {num_evaluations} evaluation queries")
        
        # Load writeup content
        try:
            writeup_content = load_writeup_content(writeup_path) if writeup_path else ""
        except Exception as e:
            if verbose:
                print(f"Warning: Could not load writeup content: {e}")
            writeup_content = ""
        
        # Format the trajectory for evaluation
        trajectory_text = self._format_trajectory_for_evaluation(trajectory)
        
        # Create evaluation prompt
        evaluation_prompt = f"""
## Task Name:
{task_name}

## Task Category:
{task_tag}

## Points:
{task_points}

## Description:
{task_description}

## Writeup Content:
{writeup_content}

## Workflow of the trajectory:
{trajectory_text}

Please evaluate this trajectory according to the criteria outlined above."""

        # Perform multiple evaluations
        evaluation_results = []
        last_response = None
        
        for eval_num in range(num_evaluations):
            if verbose:
                print(f"  Evaluation {eval_num + 1}/{num_evaluations}")
            
            for retry in range(max_retries):
                try:
                    messages = [
                        {"role": "system", "content": self.QUALITY_EVALUATION_PROMPT},
                        {"role": "user", "content": evaluation_prompt}
                    ]
                    
                    response = self.llm_client.call_model(
                        messages=messages,
                        role="assistant",
                        model_id=model_id,
                        max_retries=1  # We handle retries here
                    )
                    
                    if response is None:
                        if verbose:
                            print(f"  Retry {retry + 1}: No response from model")
                        continue
                    
                    last_response = response
                    
                    # Parse the response - look for markdown code blocks
                    result = self._parse_evaluation_response(response, verbose)
                    
                    if result is not None:
                        evaluation_results.append(result)
                        if verbose:
                            print(f"  Evaluation {eval_num + 1}: {result}")
                        break
                    else:
                        if verbose:
                            print(f"  Retry {retry + 1}: Invalid response format")
                        continue
                        
                except Exception as e:
                    if verbose:
                        print(f"  Retry {retry + 1}: Error during evaluation: {e}")
                    continue
            
            # If we couldn't get a valid response after all retries for this evaluation
            if len(evaluation_results) <= eval_num:
                if verbose:
                    print(f"  Failed to get valid response for evaluation {eval_num + 1}")
                return None, last_response
            
            # Break early if we found a low quality result
            if evaluation_results and evaluation_results[-1] is False:
                if verbose:
                    print(f"  Breaking early - trajectory is low quality")
                break
        
        # Determine final result: if ANY evaluation is False, consider it low quality
        if False in evaluation_results:
            if verbose:
                print(f"  Final result: LOW QUALITY (found at least one 'false' in {evaluation_results})")
            return False, last_response
        elif len(evaluation_results) == num_evaluations and all(evaluation_results):
            if verbose:
                print(f"  Final result: HIGH QUALITY (all {num_evaluations} evaluations were 'true')")
            return True, last_response
        else:
            if verbose:
                print(f"  Final result: EVALUATION FAILED (incomplete results: {evaluation_results})")
            return None, last_response
    
    def _format_trajectory_for_evaluation(self, trajectory: List[Dict[str, Any]]) -> str:
        """Format trajectory turns for evaluation."""
        trajectory_text = ""
        for i, turn in enumerate(trajectory):
            role = turn.get('role', '')
            content = turn.get('content', '')
            if role == "user":
                trajectory_text += f"=== Turn {i+1} (LINUX TERMINAL) ===\n{content}\n\n"
            elif role == "assistant":
                trajectory_text += f"=== Turn {i+1} (PLAYER) ===\n{content}\n\n"
            else:
                continue
        return trajectory_text
    
    def _parse_evaluation_response(self, response: str, verbose: bool = False) -> Optional[bool]:
        """Parse evaluation response to extract true/false result."""
        if verbose:
            print(f"Response: {response}")
        
        # Extract content from markdown code blocks first
        code_block_matches = re.findall(r'```(?:[a-zA-Z0-9]*\n)?(.*?)(?:\n)?```', response, re.DOTALL)
        
        if code_block_matches:
            # Use the last code block if multiple exist
            response_content = code_block_matches[-1].strip().lower()
        else:
            # Fallback to raw response if no code blocks found
            response_content = response.strip().lower()
        
        if response_content == "true":
            return True
        elif response_content == "false":
            return False
        else:
            if verbose:
                print(f"  Invalid response format: {response}")
                print(f"  Extracted content: '{response_content}'")
            return None 