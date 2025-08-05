# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
LLM client for interacting with various language models.
"""

from typing import List, Dict, Any, Optional
import litellm
from litellm import completion

from .config import Config
from .validation import ResponseValidator
from .models import ConversationTurn

# Suppress debug info from litellm
litellm.suppress_debug_info = True


class LLMClient:
    """Client for interacting with language models through litellm."""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.validator = ResponseValidator(config)
    
    def call_model(
        self,
        messages: List[Dict[str, str]],
        role: str,
        model_id: str = "deepseek-v3-0324",
        max_retries: int = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None
    ) -> Optional[str]:
        """
        Call language model with retries and validation.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content'
            role: Expected role for validation ('user' or 'assistant')
            model_id: Model identifier
            max_retries: Maximum number of retries
            temperature: Temperature for generation (uses config default if None)
            top_p: Top-p for generation (uses config default if None)
            
        Returns:
            Model response string or None if failed
        """
        max_retries = max_retries or self.config.MAX_RETRIES
        model_full_id = self.config.models.get_model_id(model_id)
        
        # Use provided parameters or fall back to config defaults
        effective_temperature = temperature if temperature is not None else self.config.temperature
        effective_top_p = top_p if top_p is not None else self.config.top_p
        
        for attempt in range(max_retries):
            try:
                response = completion(
                    model=model_full_id,
                    messages=messages,
                    temperature=effective_temperature,
                    top_p=effective_top_p,
                )['choices'][0]['message']['content']
                
                if not response:
                    raise Exception("No response from model")
                
                # Validate response
                if not self._validate_model_response(response, role):
                    raise Exception("Response validation failed")
                
                return response
                
            except Exception as e:
                print(f"Error on attempt {attempt + 1}: {e}")
                
                # Don't retry if the error is about content being too long
                if "long" in str(e):
                    return None
                
                if attempt >= max_retries - 1:
                    return None
        
        return None
    
    def _validate_model_response(self, response: str, role: str) -> bool:
        """Validate model response according to framework rules."""
        # Check colon patterns
        if not self.validator.check_colon_patterns(response, role):
            print("Colon pattern validation failed")
            return False
        
        # Check markdown balance
        if not self.validator.check_markdown_balance(response, role):
            print("Markdown balance check failed")
            return False
        
        # Check hint format
        if not self.validator.check_hint_format(response):
            print("Hint format check failed")
            return False
        
        # Validate response content
        if not self.validator.validate_response(response, role):
            print("Response content validation failed")
            return False
        
        return True
    
    def prepare_assistant_messages(
        self,
        conversation: List[ConversationTurn],
        system_prompt: str
    ) -> List[Dict[str, str]]:
        """Prepare messages for assistant model call."""
        messages = [{"role": "system", "content": system_prompt}]
        
        for turn in conversation:
            messages.append({
                "role": turn.role,
                "content": turn.content
            })
        
        # Add instruction for single code block
        if messages and messages[-1]["role"] == "user":
            messages[-1]["content"] += "\nMAKE SURE YOU ONLY INCLUDE ONE BASH MARKDOWN CODE BLOCK IN YOUR RESPONSE."
        
        return messages
    
    def prepare_user_messages(
        self,
        conversation: List[ConversationTurn],
        system_prompt: str
    ) -> List[Dict[str, str]]:
        """Prepare messages for user (terminal) model call."""
        # Build user model context: only code blocks from assistant turns, full user turns
        user_context = []
        
        for turn in conversation:
            if turn.role == "assistant":
                # Extract code block
                import re
                code_blocks = re.findall(r"```bash\n([\s\S]*?)\n```", turn.content)
                if code_blocks:
                    code_content = f"```bash\n{code_blocks[0].strip()}\n```"
                    user_context.append({"role": "user", "content": code_content})
            elif turn.role == "user":
                user_context.append({"role": "assistant", "content": turn.content})
        
        messages = [{"role": "system", "content": system_prompt}] + user_context
        return messages


class QualityEvaluator:
    """Evaluates trajectory quality using LLM."""
    
    QUALITY_PROMPT = """You are an expert and strict CTF security researcher and educator. Your task is to evaluate the quality of a CTF solving trajectory.

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
    
    def evaluate_trajectory(
        self,
        trajectory_data: Dict[str, Any],
        model_id: str = None,
        num_evaluations: int = None
    ) -> bool:
        """
        Evaluate trajectory quality.
        
        Returns True if high quality, False otherwise.
        """
        model_id = model_id or self.config.QUALITY_EVALUATION_MODEL
        num_evaluations = num_evaluations or self.config.NUM_EVALUATIONS
        
        # Build evaluation prompt
        evaluation_content = self._build_evaluation_content(trajectory_data)
        messages = [
            {"role": "system", "content": self.QUALITY_PROMPT},
            {"role": "user", "content": evaluation_content}
        ]
        
        # Perform multiple evaluations
        for _ in range(num_evaluations):
            response = self.llm_client.call_model(
                messages=messages,
                role="assistant",
                model_id=model_id,
                max_retries=3
            )
            
            if response is None:
                return False
            
            # Extract evaluation result
            import re
            code_block_match = re.search(r'```\s*(true|false)\s*```', response, re.IGNORECASE)
            if code_block_match:
                result = code_block_match.group(1).lower() == 'true'
                if not result:  # If any evaluation is false, consider it low quality
                    return False
            else:
                return False  # Invalid response format
        
        return True
    
    def _build_evaluation_content(self, trajectory_data: Dict[str, Any]) -> str:
        """Build the content for quality evaluation."""
        task_info = f"""**Task Information:**
- Name: {trajectory_data.get('task_name', '')}
- Category: {trajectory_data.get('task_tag', '')}
- Points: {trajectory_data.get('task_points', '')}
- Description: {trajectory_data.get('task_description', '')}
- Expected Solution: {trajectory_data.get('solution', '')}

**Trajectory:**
"""
        
        # Add conversation turns
        trajectory = trajectory_data.get('trajectory', [])
        for i, turn in enumerate(trajectory):
            role = turn.get('role', '')
            content = turn.get('content', '')
            task_info += f"\n**Turn {i+1} ({role.title()}):**\n{content}\n"
        
        return task_info 