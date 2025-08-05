# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Configuration management for Cyber-Zero framework.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class ModelConfig:
    """Configuration for model settings."""
    
    MODEL_MAPPINGS: Optional[Dict[str, str]] = None
    DEFAULT_TEMPERATURE: float = 0.6
    DEFAULT_TOP_P: float = 0.95
    
    def __post_init__(self):
        if self.MODEL_MAPPINGS is None:
            self.MODEL_MAPPINGS = {
                # Default research model
                "deepseek-v3-0324": "deepseek-ai/DeepSeek-V3-0324",
            }
    
    def get_model_id(self, model_key: str) -> str:
        """Get the full model ID from a model key."""
        return self.MODEL_MAPPINGS.get(model_key, model_key)


@dataclass
class ValidationConfig:
    """Configuration for validation settings."""
    
    COLON_PATTERNS: List[str] = None
    
    def __post_init__(self):
        if self.COLON_PATTERNS is None:
            self.COLON_PATTERNS = [
                "(Open file:",
                "(Current directory:",
                "(Interactive session:"
            ]


@dataclass
class Config:
    """Main configuration class for Cyber-Zero framework."""
    
    # Model settings
    models: ModelConfig = None
    
    # Validation settings  
    validation: ValidationConfig = None
    
    # Generation settings
    MAX_TURNS: int = 60  # Maximum conversation turns (30 paired turns)
    MAX_RETRIES: int = 50
    MAX_GLOBAL_RETRIES: int = 3
    DEFAULT_WORKERS: int = 16
    
    # Quality evaluation settings
    QUALITY_EVALUATION_MODEL: str = "sonnet35v2"
    NUM_EVALUATIONS: int = 1
    
    # Token limits
    TOKEN_LIMIT: int = 8192
    DEFAULT_MODEL_NAME: str = "deepseek-ai/DeepSeek-V3-0324"
    
    # Prompt paths
    ASSISTANT_PROMPT_PATH: str = "cyber_zero/prompts/assistant_turn_prompt.txt"
    USER_SYSTEM_PROMPT_PATH: str = "cyber_zero/prompts/user_turn_prompt.txt"
    
    # Model parameters (can be overridden)
    temperature: float = 0.6
    top_p: float = 0.95
    
    # Model IDs (can be overridden)
    assistant_model_id: str = "deepseek-v3-0324"
    user_model_id: str = "deepseek-v3-0324"
    
    def __post_init__(self):
        if self.models is None:
            self.models = ModelConfig()
        if self.validation is None:
            self.validation = ValidationConfig()
    
    def update_model_params(self, temperature: Optional[float] = None, top_p: Optional[float] = None):
        """Update model parameters."""
        if temperature is not None:
            self.temperature = temperature
        if top_p is not None:
            self.top_p = top_p
    
    def update_generation_params(self, max_turns: Optional[int] = None, max_retries: Optional[int] = None):
        """Update generation parameters."""
        if max_turns is not None:
            self.MAX_TURNS = max_turns
        if max_retries is not None:
            self.MAX_RETRIES = max_retries
    
    def update_model_ids(self, assistant_model_id: Optional[str] = None, user_model_id: Optional[str] = None):
        """Update model IDs."""
        if assistant_model_id is not None:
            self.assistant_model_id = assistant_model_id
        if user_model_id is not None:
            self.user_model_id = user_model_id 