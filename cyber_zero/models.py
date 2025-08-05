# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
Data models for Cyber-Zero framework.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class ConversationTurn:
    """Represents a single turn in a conversation."""
    role: str  # 'user' or 'assistant'
    content: str
    
    def __post_init__(self):
        if self.role not in ['user', 'assistant']:
            raise ValueError(f"Invalid role: {self.role}. Must be 'user' or 'assistant'")


@dataclass
class TaskMeta:
    """Metadata for a CTF task."""
    task_name: str
    task_tag: str
    task_points: str
    task_description: str
    solution: str
    task_files: List[str]
    server_description: str
    writeup_path: str
    task_writeup: Optional[str] = None
    trajectory_id: int = 0
    
    def __post_init__(self):
        # Validate required fields
        if not self.task_name:
            raise ValueError("task_name is required")
        if not self.solution:
            raise ValueError("solution is required")


@dataclass
class TrajectoryData:
    """Complete trajectory data including metadata and conversation."""
    writeup_path: str
    trajectory_id: int
    assistant_turn_count: int
    task_name: str
    task_tag: str
    task_points: str
    task_description: str
    solution: str
    trajectory: List[ConversationTurn]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrajectoryData':
        """Create TrajectoryData from dictionary representation."""
        # Convert trajectory list of dicts to ConversationTurn objects
        trajectory = [
            ConversationTurn(role=turn['role'], content=turn['content'])
            for turn in data.get('trajectory', [])
        ]
        
        return cls(
            writeup_path=data['writeup_path'],
            trajectory_id=data['trajectory_id'],
            assistant_turn_count=data['assistant_turn_count'],
            task_name=data['task_name'],
            task_tag=data['task_tag'],
            task_points=data['task_points'],
            task_description=data['task_description'],
            solution=data['solution'],
            trajectory=trajectory
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert TrajectoryData to dictionary representation."""
        return {
            'writeup_path': self.writeup_path,
            'trajectory_id': self.trajectory_id,
            'assistant_turn_count': self.assistant_turn_count,
            'task_name': self.task_name,
            'task_tag': self.task_tag,
            'task_points': self.task_points,
            'task_description': self.task_description,
            'solution': self.solution,
            'trajectory': [
                {'role': turn.role, 'content': turn.content}
                for turn in self.trajectory
            ]
        }


@dataclass
class EvaluationResult:
    """Result of trajectory quality evaluation."""
    trajectory_id: str
    is_high_quality: bool
    evaluation_details: Optional[str] = None
    model_used: Optional[str] = None
    num_evaluations: int = 1 