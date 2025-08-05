# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
from __future__ import annotations

import tempfile
import textwrap
import traceback
from abc import abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import time

from simple_parsing.helpers.serialization.serializable import FrozenSerializable

from sweagent.agent.models import APIStats, BaseModel, ContextWindowExceededError, ModelArguments
from sweagent.environment.swe_env import SWEEnv
from sweagent.environment.utils import copy_anything_to_container
from sweagent.utils.log import get_logger


@dataclass(frozen=True)
class SummarizerConfig(FrozenSerializable):
    """The configuration for the summarizer"""

    function: str = "Identity"
    window_length: int = 105
    template: str | None = None
    model: ModelArguments | None = None
    system_template: str | None = None
    instance_template: str | None = None

    def __post_init__(self):
        # Store the original function name before converting to object
        object.__setattr__(self, "_original_function_name", self.function)
        object.__setattr__(self, "function", SummarizeFunction.get(self.function, self.window_length))  # type: ignore
        if isinstance(self.model, dict):
            object.__setattr__(self, "model", ModelArguments.from_dict(self.summarizer_model))  # type: ignore

    @property
    def function_name(self) -> str:
        """Return the original function name as a string"""
        return getattr(self, "_original_function_name", self.function.__class__.__name__ if hasattr(self.function, "__class__") else "Unknown")


# ABSTRACT BASE CLASSES


class SummarizeFunctionMeta(type):
    """
    Registry maps all inherited classes to their names.
    """

    _warning_message = None

    _registry = {}

    def __new__(cls, name, bases, attrs):
        new_cls = super().__new__(cls, name, bases, attrs)
        if name != "SummarizeFunction":
            cls._registry[name] = new_cls
        return new_cls


@dataclass
class SummarizeFunction(metaclass=SummarizeFunctionMeta):
    """
    Abstract class for summarizing functions.
    We use get to generate the right summarizer based on the name of the summarizer.
    """

    def __init__(self, window_length: int):
        self._window_length = window_length
        self.logger = get_logger("summarizer")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(window_length={self._window_length})"

    def setup(self, instance_args: dict[str, Any], config):
        """
        Additional setup function for the summarizer.
        """
        pass

    @staticmethod
    def _slugify_action(action: str) -> str:
        return "".join(c if c.isalnum() else "_" for c in action)[:50]

    @staticmethod
    def _upload_file_to_container(file_content: str, file_path_on_container: str, env: SWEEnv):
        assert env.container_obj is not None
        env.communicate(f'mkdir -p "{Path(file_path_on_container).parent}"')
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(file_content.encode("utf-8"))
            fp.flush()
            copy_anything_to_container(env.container_obj, fp.name, file_path_on_container)

    @abstractmethod
    def __call__(self, input: str, observation, env: SWEEnv, model: type[BaseModel]) -> tuple[str, APIStats]:
        """
        Abstract method for getting an observation and summarize it.
        The returned value should be a summation of the given observation.
        """
        raise NotImplementedError

    @classmethod
    def get(cls, name: str, window_length: int):
        try:
            return cls._registry[name](window_length)
        except KeyError:
            msg = f"Model output summarizer ({name}) not found."
            raise ValueError(msg)


# DEFINE NEW SUMMARIZE FUNCTIONS BELOW THIS LINE


class SimpleSummarizer(SummarizeFunction):
    """
    Saves the output of the command to a file and uses the open command to show the output.
    """

    _warning_message = """\
        Warning: Command output exceeded window, saved command to a file {command_file_name}. Use 'open {command_file_name}' to view the full output.


    """

    block_list_input = [
        "create",
        "open",
        "edit",
        "scroll_up",
        "scroll_down",
        "goto",
        "search_file",
        "search_dir",
    ]

    def __call__(self, input: str, observation: str, env: SWEEnv, model: BaseModel) -> tuple[str, APIStats]:
        try:
            # More robust blocking: check if the command (first word) is in block list
            command_name = input.strip().split()[0] if input.strip() else ""
            if (
                command_name in self.block_list_input
                or len(observation.splitlines()) <= self._window_length
            ):
                return observation, APIStats()
            
            self.logger.debug(f"Summarizing current observation for input {input}")
            # Use unique filenames with timestamp to avoid any collision issues
            timestamp = str(int(time.time() * 1000))  # milliseconds for uniqueness  
            command_slug = self._slugify_action(input)
            command_file_name = f"/output/{command_slug}_{timestamp}"
            
            # For all non-blocked commands, use the standard behavior
            self._upload_file_to_container(observation, command_file_name, env)
            
            # Create the warning message but don't open the file to avoid changing CURRENT_FILE
            warning_message = textwrap.dedent(self._warning_message.format(command_file_name=command_file_name))
            
            # Instead of opening the file (which would change CURRENT_FILE), just show a preview
            preview_lines = observation.splitlines()[:10]  # Show first 10 lines as preview
            preview = "\n".join(preview_lines)
            if len(observation.splitlines()) > 10:
                preview += f"\n\n... ({len(observation.splitlines()) - 10} more lines in {command_file_name})"
            
            return warning_message + preview, APIStats()
                
        except Exception:
            self.logger.warning(
                f"Unhandled exception occurred when trying to summarize observation for input {input}: {traceback.format_exc()}"
            )
            return observation, APIStats()


class Identity(SummarizeFunction):
    """
    This summarizer does not do any summation. It returns the environment observation as is.
    """

    def __call__(self, input: str, observation: str, env: SWEEnv, model: type[BaseModel]) -> tuple[str, APIStats]:
        """
        This doesn't do any summarization. It just returns the environment observation.
        """
        return observation, APIStats()


class LMSummarizer(SummarizeFunction):
    _warning_message = """\
    Warning: Command output exceeded window size, saved command to a file {command_file_name} and summarized the command output for you.
    If you still want to view the output of the command, use the following command `open {command_file_name}`.


    SUMMARY:
    """

    _warning_message_summarization_failed = """\
    Warning: Command output exceeded window size, saved command to a file {command_file_name}.
    If you still want to view the output of the command, use the following command `open {command_file_name}`.
    """

    block_list_input = [
        "create",
        "open",
        "edit",
        "scroll_up",
        "scroll_down",
        "goto",
        "search_file",
        "search_dir",
    ]

    fail_back_to_simple_summarizer_input = [
        "xxd",
        "hexdump",
        "strings",
    ]

    lm_summarizer_char_limit = 200000

    def __init__(self, window_length: int):
        super().__init__(window_length)
        self.history = []
        self._simple_summarizer = SimpleSummarizer(window_length=window_length)

    def setup(self, instance_args: dict[str, Any], config):
        self.name = "ctf_summarizer"
        self.system_args = config.__dict__
        self.system_args.update({f"summarizer_{k}": v for k, v in config.summarizer_config.__dict__.items()})
        system_msg = config.summarizer_config.system_template.format(**self.system_args)
        self.history.append({"role": "system", "content": system_msg, "agent": self.name})
        self.logger.info(f"SYSTEM ({self.name})\n{system_msg}")
        self.instance_template = config.summarizer_config.instance_template
        self.instance_args = instance_args

    def __call__(self, input: str, observation: str, env: SWEEnv, model: BaseModel) -> tuple[str, APIStats]:
        try:
            # More robust blocking: check if the command (first word) is in block list
            command_name = input.strip().split()[0] if input.strip() else ""
            if (
                command_name in self.block_list_input
                or len(observation.splitlines()) <= self._window_length
            ):
                return observation, APIStats()
            if len(observation) > self.lm_summarizer_char_limit or any(
                input.startswith(s) for s in self.fail_back_to_simple_summarizer_input
            ):
                self.logger.warning("Observation is too long for LMSummarizer, using SimpleSummarizer instead")
                return self._simple_summarizer(input, observation, env, model)
            self.logger.debug(f"Summarizing current observation for input {input}")
            # Use unique filenames with timestamp to avoid any collision issues
            timestamp = str(int(time.time() * 1000))  # milliseconds for uniqueness  
            command_slug = self._slugify_action(input)
            command_file_name = f"/output/{command_slug}_{timestamp}"
            
            # For all non-blocked commands, use the standard behavior
            self._upload_file_to_container(observation, command_file_name, env)
            summarization_content = observation
            
            self.history.append(
                {
                    "role": "user",
                    "content": self.instance_template.format(
                        **self.instance_args, **self.system_args, command=input, observation=summarization_content
                    ),
                    "agent": self.name,
                }
            )
            self.logger.debug(f"Summarizer history")
            response = model.query(history=self.history)
            stats = model.stats
            model.reset_stats(APIStats())
            self.history.pop()
            return textwrap.dedent(self._warning_message.format(command_file_name=command_file_name)) + response, stats
        except ContextWindowExceededError:
            return textwrap.dedent(
                self._warning_message_summarization_failed.format(command_file_name=command_file_name)
            ), APIStats()
        except Exception:
            self.logger.warning(
                f"Unhandled exception occurred when trying to summarize observation for input {input}: {traceback.format_exc()}"
            )
            return observation, APIStats()


# Custom YAML representers for better serialization
def summarize_function_representer(dumper, data):
    """Custom YAML representer for SummarizeFunction objects"""
    return dumper.represent_scalar('tag:yaml.org,2002:str', data.__class__.__name__)


# Register the custom representers for all SummarizeFunction subclasses
try:
    import yaml
    yaml.add_representer(SummarizeFunction, summarize_function_representer)
    yaml.add_representer(SimpleSummarizer, summarize_function_representer)  
    yaml.add_representer(Identity, summarize_function_representer)
    yaml.add_representer(LMSummarizer, summarize_function_representer)
except ImportError:
    # yaml might not be available in all contexts
    pass
