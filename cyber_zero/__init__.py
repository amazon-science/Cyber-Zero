# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Cyber-Zero: CTF Trajectory Generation and Analysis Framework

A comprehensive framework for generating, evaluating, and analyzing
AI agent trajectories in Capture The Flag (CTF) cybersecurity challenges.
"""

__version__ = "1.0.0"
__author__ = "Cyber-Zero Team"

from .models import TrajectoryData, TaskMeta, ConversationTurn
from .config import Config
from .trajectory_generator import TrajectoryGenerator
from .quality_evaluator import TrajectoryQualityEvaluator
from .trajectory_reformatter import TrajectoryReformatter
from .validation import ResponseValidator
from .llm_client import LLMClient

__all__ = [
    "TrajectoryData",
    "TaskMeta", 
    "ConversationTurn",
    "Config",
    "TrajectoryGenerator",
    "TrajectoryQualityEvaluator", 
    "TrajectoryReformatter",
    "ResponseValidator",
    "LLMClient",
] 