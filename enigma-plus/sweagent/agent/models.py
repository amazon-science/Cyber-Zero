# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
from __future__ import annotations

import copy
import json
import logging
import yaml
from collections import defaultdict
from dataclasses import dataclass, fields
from pathlib import Path
import boto3
from botocore.config import Config
import together
from anthropic import AI_PROMPT, HUMAN_PROMPT, Anthropic, AnthropicBedrock
from groq import Groq
from openai import AzureOpenAI, BadRequestError, OpenAI
from simple_parsing.helpers.serialization.serializable import FrozenSerializable, Serializable
from tenacity import (
    retry,
    retry_if_not_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

from sweagent.agent.commands import Command
from sweagent.utils.config import keys_config
from sweagent.utils.log import get_logger
import requests  # Add this import for HTTP requests
import re

logger = get_logger("api_models")

_MAX_RETRIES = int(keys_config.get("SWE_AGENT_MODEL_MAX_RETRIES", 10))

# Load model configurations from YAML
def load_model_configs():
    """Load model configurations from YAML file"""
    config_path = Path(__file__).parent.parent / "models_config.yaml"
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    return config

def get_model_metadata(model_name: str, provider_configs: dict, shortcuts: dict, defaults: dict) -> dict:
    """Get model metadata with default values for missing fields"""
    # Check shortcuts first
    actual_model = shortcuts.get(model_name, model_name)
    
    # Get model config
    model_config = provider_configs.get(actual_model, {})
    
    # Apply defaults for missing values
    metadata = {
        'max_context': model_config.get('max_context', defaults['max_context']),
        'cost_per_input_token': model_config.get('cost_per_input_token', defaults['cost_per_input_token']),
        'cost_per_output_token': model_config.get('cost_per_output_token', defaults['cost_per_output_token']),
    }
    
    # Add optional fields if present
    if 'max_tokens' in model_config:
        metadata['max_tokens'] = model_config['max_tokens']
    elif 'max_tokens' in defaults:
        metadata['max_tokens'] = defaults['max_tokens']
    
    return metadata

def clean_result(result):
    # First, split on </think> and take everything after the first one (if any)
    if "</think>" in result:
        content = " ".join(result.split("</think>")[1:])
    else:
        content = result
    content = content.split("<|im_end|>")[0]
    
    # print(f"Content: {result}")
    # exit()
    # # Now, remove all <|...|> patterns including Unicode variants
    import re
    # # Remove all <|...|> patterns - this pattern matches < followed by any pipe-like character, then any content, then pipe-like character and >
    
    # Also remove specific tool call patterns
    tool_patterns = [
        r"<｜tool▁call▁begin｜>.*?<｜tool▁call▁end｜>",
        r"<｜tool▁calls▁begin｜>.*?<｜tool▁calls▁end｜>",
    ]
    # Use a loop to handle nested patterns
    for pattern in tool_patterns:
        while re.search(pattern, content, flags=re.DOTALL):
            content = re.sub(pattern, "", content, flags=re.DOTALL)

    content = content.replace("<｜tool▁call▁begin｜>", "").replace("<｜tool▁call▁end｜>", "").replace("<｜tool▁calls▁begin｜>", "").replace("<｜tool▁calls▁end｜>", "")
    
    return content.strip()

@dataclass(frozen=True)
class ModelArguments(FrozenSerializable):
    """Arguments configuring the model and its behavior."""

    # Name of the model to use
    model_name: str
    # Cost limit for every instance (task)
    per_instance_cost_limit: float = 0.0
    # Total cost limit
    total_cost_limit: float = 0.0
    # Sampling temperature
    temperature: float = 0.0
    # Sampling top-p
    top_p: float = 1.0
    # Sampling top-k
    top_k: int = 20
    # Path to replay file when using the replay model
    replay_path: str | None = None
    # Host URL when using Ollama model
    host_url: str = "localhost:11434"
    # Maximum number of steps (environment interactions) per instance (0 = unlimited)
    per_instance_step_limit: int = 0


@dataclass
class APIStats(Serializable):
    total_cost: float = 0
    instance_cost: float = 0
    tokens_sent: int = 0
    tokens_received: int = 0
    api_calls: int = 0

    def __add__(self, other):
        if not isinstance(other, APIStats):
            msg = "Can only add APIStats with APIStats"
            raise TypeError(msg)

        return APIStats(
            **{field.name: getattr(self, field.name) + getattr(other, field.name) for field in fields(self)},
        )

    def replace(self, other):
        if not isinstance(other, APIStats):
            msg = "Can only replace APIStats with APIStats"
            raise TypeError(msg)

        return APIStats(**{field.name: getattr(other, field.name) for field in fields(self)})


class ContextWindowExceededError(Exception):
    pass


class CostLimitExceededError(Exception):
    pass


class BaseModel:
    def __init__(self, args: ModelArguments, commands: list[Command]):
        self.args = args
        self.commands = commands
        self.model_metadata = {}
        self.stats = APIStats()

        # Load configurations from YAML
        configs = load_model_configs()
        defaults = configs['defaults']
        
        # Get provider-specific configs and shortcuts
        provider_configs, shortcuts = self._get_provider_configs(configs)
        
        # Map `model_name` to API-compatible name `api_model`
        self.api_model = shortcuts.get(self.args.model_name, self.args.model_name)

        # Handle special model name prefixes
        if args.model_name.startswith("ft:"):
            ft_model = args.model_name.split(":")[1]
            self.model_metadata = get_model_metadata(ft_model, provider_configs, shortcuts, defaults)
        elif args.model_name.startswith("ollama:"):
            self.api_model = args.model_name.split("ollama:", 1)[1]
            # Ollama models use default metadata
            self.model_metadata = get_model_metadata(self.api_model, {}, {}, defaults)
        elif args.model_name.startswith("azure:"):
            azure_model = args.model_name.split("azure:", 1)[1]
            self.model_metadata = get_model_metadata(azure_model, provider_configs, shortcuts, defaults)
        elif args.model_name.startswith("bedrock:"):
            self.api_model = args.model_name.split("bedrock:", 1)[1]
            bedrock_configs = configs.get('bedrock_models', {})
            self.model_metadata = get_model_metadata(self.api_model, bedrock_configs, {}, defaults)
        elif args.model_name.startswith("groq:"):
            self.api_model = args.model_name.split("groq:", 1)[1]
            groq_configs = configs.get('groq_models', {})
            groq_shortcuts = configs.get('groq_shortcuts', {})
            self.model_metadata = get_model_metadata(self.api_model, groq_configs, groq_shortcuts, defaults)
        elif args.model_name.startswith("vllm:"):
            # VLLM models use default metadata
            self.model_metadata = get_model_metadata(self.args.model_name, {}, {}, defaults)
        else:
            # Try to find model in any provider configs
            self.model_metadata = get_model_metadata(args.model_name, provider_configs, shortcuts, defaults)
            
            # If model not found anywhere, check special models
            if not any(key in self.model_metadata for key in ['max_context']) or self.model_metadata.get('max_context') == defaults['max_context']:
                special_configs = configs.get('special_models', {})
                if args.model_name in special_configs:
                    self.model_metadata = get_model_metadata(args.model_name, special_configs, {}, defaults)
                elif self.api_model not in provider_configs and args.model_name not in shortcuts:
                    msg = f"Unregistered model ({args.model_name}). Add model to models_config.yaml"
                    logger.warning(msg)
                    # Use defaults for unknown models
                    self.model_metadata = defaults.copy()

    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        """Get the appropriate provider configs and shortcuts based on model class"""
        # This method should be overridden by subclasses to return the right configs
        return {}, {}

    def reset_stats(self, other: APIStats | None = None):
        if other is None:
            self.stats = APIStats(total_cost=self.stats.total_cost)
            logger.info("Resetting model stats")
        else:
            # Make sure to copy the stats to avoid modifying the original
            self.stats = copy.deepcopy(other)

    def update_stats(self, input_tokens: int, output_tokens: int) -> float:
        """
        Calculates the cost of a response from the openai API.

        Args:
        input_tokens (int): The number of tokens in the prompt.
        output_tokens (int): The number of tokens in the response.

        Returns:
        float: The cost of the response.
        """
        # Calculate cost and update cost related fields
        cost = (
            self.model_metadata.get("cost_per_input_token", 0.0) * input_tokens
            + self.model_metadata.get("cost_per_output_token", 0.0) * output_tokens
        )
        self.stats.total_cost += cost
        self.stats.instance_cost += cost
        self.stats.tokens_sent += input_tokens
        self.stats.tokens_received += output_tokens
        self.stats.api_calls += 1

        # Log updated cost values to std. err
        logger.debug(
            f"input_tokens={input_tokens:,}, "
            f"output_tokens={output_tokens:,}, "
            f"instance_cost={self.stats.instance_cost:.2f}, "
            f"cost={cost:.2f}",
        )
        logger.debug(
            f"total_tokens_sent={self.stats.tokens_sent:,}, "
            f"total_tokens_received={self.stats.tokens_received:,}, "
            f"total_cost={self.stats.total_cost:.2f}, "
            f"total_api_calls={self.stats.api_calls:,}",
        )

        # Check whether total cost or instance cost limits have been exceeded
        if 0 < self.args.total_cost_limit <= self.stats.total_cost:
            logger.warning(f"Cost {self.stats.total_cost:.2f} exceeds limit {self.args.total_cost_limit:.2f}")
            msg = "Total cost limit exceeded"
            raise CostLimitExceededError(msg)

        if 0 < self.args.per_instance_cost_limit <= self.stats.instance_cost:
            logger.warning(f"Cost {self.stats.instance_cost:.2f} exceeds limit {self.args.per_instance_cost_limit:.2f}")
            msg = "Instance cost limit exceeded"
            raise CostLimitExceededError(msg)
        return cost

    def query(self, history: list[dict[str, str]]) -> str:
        msg = "Use a subclass of BaseModel"
        raise NotImplementedError(msg)


class OpenAIModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('openai_models', {}), configs.get('openai_shortcuts', {})

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)

        logging.getLogger("openai").setLevel(logging.WARNING)
        logging.getLogger("httpx").setLevel(logging.WARNING)

        self._setup_client()
        # Track all previous responses to detect duplicates
        self.previous_responses = []

    def _setup_client(self):
        if self.args.model_name.startswith("azure"):
            logger.warning(
                "The --model CLI argument is ignored when using the Azure GPT endpoint. "
                "The model is determined by the AZURE_OPENAI_DEPLOYMENT key/"
                "environment variable (this might change in the future).",
            )
            self.api_model = keys_config["AZURE_OPENAI_DEPLOYMENT"]
            self.client = AzureOpenAI(
                api_key=keys_config["AZURE_OPENAI_API_KEY"],
                azure_endpoint=keys_config["AZURE_OPENAI_ENDPOINT"],
                api_version=keys_config.get("AZURE_OPENAI_API_VERSION", "2024-02-01"),
            )
        else:
            api_base_url: str | None = keys_config.get("OPENAI_API_BASE_URL", None)
            self.client = OpenAI(api_key=keys_config["OPENAI_API_KEY"], base_url=api_base_url)

    def history_to_messages(
        self,
        history: list[dict[str, str]],
        is_demonstration: bool = False,
    ) -> str | list[dict[str, str]]:
        """
        Create `messages` by filtering out all keys except for role/content per `history` turn
        """
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
            return "\n".join([entry["content"] for entry in history])
        # Return history components with just role, content fields
        return [{k: v for k, v in entry.items() if k in ["role", "content"]} for entry in history]

    @retry(
        wait=wait_random_exponential(min=1, max=15),
        reraise=True,
        stop=stop_after_attempt(_MAX_RETRIES),
        retry=retry_if_not_exception_type((CostLimitExceededError, RuntimeError)),
    )
    def query(self, history: list[dict[str, str]]) -> str:
        """
        Query the OpenAI API with the given `history` and return the response.
        """
        max_resample_attempts = 10
        resample_count = 0
        
        while resample_count < max_resample_attempts:
            try:
                # Perform OpenAI API call
                response = self.client.chat.completions.create(
                    messages=self.history_to_messages(history),
                    model=self.api_model,
                    temperature=self.args.temperature,
                    top_p=self.args.top_p,
                )
                break
            except BadRequestError as e:
                logger.exception("BadRequestError")
                if "context window" in str(e) or getattr(e, "error", {}).get("code") == "context_length_exceeded":
                    msg = f"Context window ({self.model_metadata.get('max_context', 'unknown')} tokens) exceeded"
                    raise ContextWindowExceededError(msg) from e
                else:
                    raise e
            
        # Calculate + update costs, get response
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        self.update_stats(input_tokens, output_tokens)
        current_response = clean_result(response.choices[0].message.content)
        
        # Store this response for future comparison
        self.previous_responses.append(current_response.strip())
        return current_response


class DeepSeekModel(OpenAIModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('deepseek_models', {}), {}

    def _setup_client(self) -> None:
        api_base_url: str = keys_config["DEEPSEEK_API_BASE_URL"]
        self.client = OpenAI(api_key=keys_config["DEEPSEEK_API_KEY"], base_url=api_base_url)


class GroqModel(OpenAIModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('groq_models', {}), configs.get('groq_shortcuts', {})

    def _setup_client(self) -> None:
        self.client = Groq(
            api_key=keys_config["GROQ_API_KEY"],
        )


class AnthropicModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('anthropic_models', {}), configs.get('anthropic_shortcuts', {})

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)

        # Set Anthropic key
        self.api = Anthropic(api_key=keys_config["ANTHROPIC_API_KEY"])

    def history_to_messages(
        self,
        history: list[dict[str, str]],
        is_demonstration: bool = False,
    ) -> str | list[dict[str, str]]:
        """
        Create `prompt` by filtering out all keys except for role/content per `history` turn
        Reference: https://docs.anthropic.com/claude/reference/complete_post
        """
        return anthropic_history_to_messages(self, history, is_demonstration)

    @retry(
        wait=wait_random_exponential(min=1, max=15),
        reraise=True,
        stop=stop_after_attempt(_MAX_RETRIES),
        retry=retry_if_not_exception_type((CostLimitExceededError, RuntimeError)),
    )
    def query(self, history: list[dict[str, str]]) -> str:
        """
        Query the Anthropic API with the given `history` and return the response.
        """
        return anthropic_query(self, history)


class BedrockModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)

        # Extract provider from model ID
        # https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids.html
        self.model_provider = self.api_model.split(".")[0]
        if self.model_provider == "anthropic":
            # Note: this assumes AWS credentials are already configured.
            # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html
            self.api = AnthropicBedrock()
        elif self.model_provider == "us":
            # For DeepSeek models, use native Bedrock client
            config = Config(
                retries={
                    "max_attempts": 100,
                    "mode": "standard"
                }
            )
            self.api = boto3.client('bedrock-runtime', config=config, region_name='us-west-2')
        elif self.model_provider in ["ai21", "amazon", "cohere", "meta", "mistral"]:
            msg = f"{self.api_model} is not supported!"
            raise NotImplementedError(msg)
        else:
            msg = f"Provider {self.model_provider} is not supported by Amazon Bedrock!"
            raise ValueError(msg)

    def history_to_messages(
        self,
        history: list[dict[str, str]],
        is_demonstration: bool = False,
    ) -> str | list[dict[str, str]]:
        """
        Create `prompt` from the history of messages
        """
        if self.model_provider == "anthropic":
            return anthropic_history_to_messages(self, history, is_demonstration)
        elif self.model_provider == "us":
            # For DeepSeek models, return messages in standard format
            if is_demonstration:
                history = [entry for entry in history if entry["role"] != "system"]
                return "\n".join([entry["content"] for entry in history])
            return [{k: v for k, v in entry.items() if k in ["role", "content"]} for entry in history]
        else:
            msg = f"{self.api_model} is not supported!"
            raise NotImplementedError(msg)

    @retry(
        wait=wait_random_exponential(min=1, max=15),
        reraise=True,
        stop=stop_after_attempt(_MAX_RETRIES),
        retry=retry_if_not_exception_type((CostLimitExceededError, RuntimeError)),
    )
    def query(self, history: list[dict[str, str]]) -> str:
        """
        Query Amazon Bedrock with the given `history` and return the response.
        """
        if self.model_provider == "anthropic":
            return anthropic_query(self, history)
        elif self.model_provider == "us":
            for _ in range(5):
                response = deepseek_query(self, history)
                if response:
                    return response
            
            msg = f"{self.api_model} is not supported!"
            raise NotImplementedError(msg)


def deepseek_query(model: BedrockModel, history: list[dict[str, str]]) -> str:
    """
    Query DeepSeek models via Amazon Bedrock with the given `history` and return the response.
    """
    # Get system message(s) and user messages
    system_message = "\n".join([entry["content"] for entry in history if entry["role"] == "system"])
    
    # Convert messages to Bedrock format
    messages = []
    for entry in history:
        if entry["role"] != "system":  # Skip system messages as they're handled separately
            # Ensure content is not empty
            content = entry.get("content", "").strip()
            if content:  # Only add non-empty messages
                messages.append({
                    "role": entry["role"],
                    "content": [{"text": content}]
                })
    
    # Ensure we have at least one message
    if not messages:
        # If no messages, add a default user message
        messages = [{"role": "user", "content": [{"text": "Hello"}]}]
    
    # Prepare system prompts - only include if there's a system message
    system_prompts = [{"text": system_message}] if system_message.strip() else None

    # Configure inference parameters
    inference_config = {
        "temperature": max(0.0, min(1.0, model.args.temperature)),  # Clamp temperature between 0 and 1
        "maxTokens": model.model_metadata.get("max_tokens", 4096),  # Ensure maxTokens doesn't exceed limits
    }
    
    # Add top_p if it's not the default value
    if model.args.top_p != 1.0:
        inference_config["topP"] = max(0.0, min(1.0, model.args.top_p))  # Clamp topP between 0 and 1
    
    # Prepare converse parameters
    converse_params = {
        "modelId": model.api_model,
        "messages": messages,
        "inferenceConfig": inference_config,
    }
    
    # Only add system prompts if they exist
    if system_prompts:
        converse_params["system"] = system_prompts
    
    # Perform Bedrock API call using converse method
    response = model.api.converse(**converse_params)
    
    # Extract the response content
    output_message = response["output"]["message"]
    response_text = ""
        # Handle reasoning content and regular content
    for content in output_message["content"]:
        if content.get("reasoningContent"):
            # Skip reasoning content for now, but could be included if needed
            continue
        else:
            response_text = content["text"].split("(Open file:")[0].strip()
            break

    # Calculate token usage for cost tracking
    usage = response.get("usage", {})
    input_tokens = usage.get("inputTokens", 0)
    output_tokens = usage.get("outputTokens", 0)
    
    # Update stats and return response
    if response_text:
        model.update_stats(input_tokens, output_tokens)
        return response_text


class OllamaModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('ollama_models', {}), configs.get('ollama_shortcuts', {})

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)
        from ollama import Client

        self.client = Client(host=args.host_url)

    def history_to_messages(
        self,
        history: list[dict[str, str]],
        is_demonstration: bool = False,
    ) -> str | list[dict[str, str]]:
        """
        Create `messages` by filtering out all keys except for role/content per `history` turn
        """
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
            return "\n".join([entry["content"] for entry in history])
        # Return history components with just role, content fields
        return [{k: v for k, v in entry.items() if k in ["role", "content"]} for entry in history]

    @retry(
        wait=wait_random_exponential(min=1, max=15),
        reraise=True,
        stop=stop_after_attempt(_MAX_RETRIES),
        retry=retry_if_not_exception_type((CostLimitExceededError, RuntimeError)),
    )
    def query(self, history: list[dict[str, str]]) -> str:
        """
        Query the Ollama API with the given `history` and return the response.
        """
        response = self.client.chat(
            model=self.api_model,
            messages=self.history_to_messages(history),
            options={
                "temperature": self.args.temperature,
                "top_p": self.args.top_p,
            },
        )
        # Calculate + update costs, return response
        if "prompt_eval_count" in response:
            input_tokens = response["prompt_eval_count"]
        else:
            logger.warning(
                "Prompt eval count not found in response. Using 0. "
                "This might be because the prompt has been cached. "
                "See https://github.com/swe-agent/SWE-agent/issues/44 "
                "and https://github.com/ollama/ollama/issues/3427.",
            )
            input_tokens = 0
        output_tokens = response["eval_count"]
        self.update_stats(input_tokens, output_tokens)
        return response["message"]["content"]


class TogetherModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return configs.get('together_models', {}), configs.get('together_shortcuts', {})

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)
        assert together.version >= "1.1.0", "Please upgrade to Together SDK v1.1.0 or later."

        # Set Together key
        together.api_key = keys_config["TOGETHER_API_KEY"]

    def history_to_messages(self, history: list[dict[str, str]], is_demonstration: bool = False) -> str:
        """
        Create `prompt` by filtering out all keys except for role/content per `history` turn
        """
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
        # Map history to TogetherAI format
        mapping = {"user": "human", "assistant": "bot", "system": "bot"}
        prompt = [f'<{mapping[d["role"]]}>: {d["content"]}' for d in history]
        prompt = "\n".join(prompt)
        return f"{prompt}\n<bot>:"

    @retry(
        wait=wait_random_exponential(min=1, max=15),
        reraise=True,
        stop=stop_after_attempt(_MAX_RETRIES),
        retry=retry_if_not_exception_type((CostLimitExceededError, RuntimeError)),
    )
    def query(self, history: list[dict[str, str]]) -> str:
        """
        Query the Together API with the given `history` and return the response.
        """
        # Perform Together API call
        prompt = self.history_to_messages(history)
        # Anthropic's count_tokens is convenient because it caches and utilizes huggingface/tokenizers, so we will use.
        max_tokens_to_sample = self.model_metadata.get("max_context", 32768) - Anthropic().count_tokens(prompt)
        completion = together.Complete.create(
            model=self.api_model,
            prompt=prompt,
            max_tokens=max_tokens_to_sample,
            stop=["<human>"],
            temperature=self.args.temperature,
            top_p=self.args.top_p,
        )
        # Calculate + update costs, return response
        response = completion["choices"][0]["text"].split("<human>")[0]
        input_tokens = completion["usage"]["prompt_tokens"]
        output_tokens = completion["usage"]["completion_tokens"]
        self.update_stats(input_tokens, output_tokens)
        return response


class HumanModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)

        # Determine which commands require multi-line input
        self.multi_line_command_endings = {
            command.name: command.end_name for command in commands if command.end_name is not None
        }

    def history_to_messages(
        self,
        history: list[dict[str, str]],
        is_demonstration: bool = False,
    ) -> str | list[dict[str, str]]:
        """
        Create `messages` by filtering out all keys except for role/content per `history` turn
        """
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
            return "\n".join([entry["content"] for entry in history])
        # Return history components with just role, content fields
        return [{k: v for k, v in entry.items() if k in ["role", "content"]} for entry in history]

    def query(self, history: list[dict[str, str]], action_prompt: str = "> ") -> str:
        """
        Logic for handling user input to pass to SWEEnv
        """
        action = input(action_prompt)
        command_name = action.split()[0] if action.strip() else ""

        # Special handling for multi-line input actions (i.e. edit)
        if command_name in self.multi_line_command_endings:
            buffer = [action]
            end_keyword = self.multi_line_command_endings[command_name]
            while True:
                action = input("... ")
                buffer.append(action)
                if action.rstrip() == end_keyword:
                    # Continue reading input until terminating keyword inputted
                    break
            action = "\n".join(buffer)
        elif action.strip() == "start_multiline_command":  # do arbitrary multi-line input
            buffer = []
            while True:
                action = input("... ")
                if action.rstrip() == "end_multiline_command":
                    break
                buffer.append(action)
            action = "\n".join(buffer)
        return action


class HumanThoughtModel(HumanModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def query(self, history: list[dict[str, str]]) -> str:
        """
        Logic for handling user input (both thought + action) to pass to SWEEnv
        """
        thought_all = ""
        thought = input("Thought (end w/ END_THOUGHT): ")
        while True:
            if "END_THOUGHT" in thought:
                thought = thought.split("END_THOUGHT")[0]
                thought_all += thought
                break
            thought_all += thought
            thought = input("... ")

        action = super().query(history, action_prompt="Action: ")

        return f"{thought_all}\n```\n{action}\n```"


class ReplayModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def __init__(self, args: ModelArguments, commands: list[Command]):
        super().__init__(args, commands)

        if self.args.replay_path is None or not Path(self.args.replay_path).exists():
            msg = "--replay_path must point to a file that exists to run a replay policy"
            raise ValueError(msg)

        self.replays = [
            list(json.loads(x).values())[0] for x in Path(self.args.replay_path).read_text().splitlines(keepends=True)
        ]
        self.replay_idx = 0
        self.action_idx = 0

    def _next_replay(self) -> None:
        """Called after last action"""
        self.replay_idx += 1
        self.action_idx = 0

    def query(self, history: list[dict[str, str]]) -> str:
        """
        Logic for tracking which replay action to pass to SWEEnv
        """
        actions = self.replays[self.replay_idx]
        try:
            action = actions[self.action_idx]
        except IndexError:
            msg = (
                "This seems to be an incomplete trajectory. "
                "We reached the end of it, but `submit` was not called. "
                "Calling it now."
            )
            logger.warning(msg)
            action = "```\nsubmit\n```"

        self.action_idx += 1

        # Assuming `submit` is always last action of replay trajectory
        if action == "submit":
            self._next_replay()

        return action


class InstantEmptySubmitTestModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def __init__(self, args: ModelArguments, commands: list[Command]):
        """This model immediately submits. Useful for testing purposes"""
        super().__init__(args, commands)
        self._action_idx = 0

    def query(self, history: list[dict[str, str]]) -> str:
        # Need to at least do _something_ to submit
        if self._action_idx == 0:
            self._action_idx = 1
            action = "DISCUSSION\nLet's reproduce the bug by creating a `reproduce.py` file.\n\n```\ncreate reproduce.py\n```\n"
        elif self._action_idx == 1:
            self._action_idx = 0
            action = "DISCUSSION\nThe task should be resolved, so let's submit the patch.\n\n```\nsubmit\n```\n"
        self.update_stats(0, 0)
        return action


class VLLMModel(BaseModel):
    def _get_provider_configs(self, configs: dict) -> tuple[dict, dict]:
        return {}, {}

    def __init__(self, args: ModelArguments, commands: list[Command]):
        # Parse model name and host
        if ":" in args.model_name:
            # e.g. vllm:Qwen/Qwen3-32B
            _, model_name = args.model_name.split(":", 1)
        else:
            model_name = args.model_name
        
        # Create a new ModelArguments with the correct model_name, preserving other fields
        new_args = ModelArguments(
            model_name=model_name,
            per_instance_cost_limit=args.per_instance_cost_limit,
            total_cost_limit=args.total_cost_limit,
            temperature=args.temperature,
            top_p=args.top_p,
            top_k=args.top_k,
            replay_path=args.replay_path,
            host_url=args.host_url,
            per_instance_step_limit=args.per_instance_step_limit,
        )
        super().__init__(new_args, commands)
        self.vllm_model = model_name
        self.host_url = getattr(args, "host_url", "http://localhost:8000")
        if not self.host_url.startswith("http"):
            self.host_url = f"http://{self.host_url}"
        self.api_url = f"{self.host_url}/v1/chat/completions"

    def history_to_messages(self, history: list[dict[str, str]], is_demonstration: bool = False) -> list[dict[str, str]]:
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
            return [{"role": entry["role"], "content": entry["content"]} for entry in history]
        return [{"role": entry["role"], "content": entry["content"]} for entry in history]

    def query(self, history: list[dict[str, str]]) -> str:
        payload = {
            "model": self.vllm_model,
            "messages": self.history_to_messages(history),
            "temperature": self.args.temperature,
            "top_p": self.args.top_p,
            "top_k": self.args.top_k,
        }
        try:
            response = requests.post(self.api_url, json=payload, timeout=3600)
            response.raise_for_status()
            data = response.json()
            # vLLM returns choices[0].message.content
            result = data["choices"][0]["message"]["content"]
            # Use token usage if available
            usage = data.get("usage", {})
            input_tokens = usage.get("prompt_tokens", 0)
            output_tokens = usage.get("completion_tokens", 0)
            self.update_stats(input_tokens, output_tokens)
            return clean_result(result)
        except Exception as e:
            logger.error(f"vLLM API error: {e}")
            raise


def anthropic_history_to_messages(
    model: AnthropicModel | BedrockModel,
    history: list[dict[str, str]],
    is_demonstration: bool = False,
) -> str | list[dict[str, str]]:
    """
    Create `prompt` by filtering out all keys except for role/content per `history` turn
    Reference: https://docs.anthropic.com/claude/reference/complete_post
    """
    # Preserve behavior for older models
    if model.api_model in ["claude-instant", "claude-2.0"] or (
        isinstance(model, BedrockModel) and model.api_model in ["anthropic.claude-instant-v1", "anthropic.claude-v2"]
    ):
        # Remove system messages if it is a demonstration
        if is_demonstration:
            history = [entry for entry in history if entry["role"] != "system"]
        # Map history to Claude format
        prompt = "\n\n"
        for entry in history:
            if entry["role"] in {"user", "system"}:
                prompt += f'{HUMAN_PROMPT} {entry["content"]}\n\n'
            elif entry["role"] == "assistant":
                prompt += f'{AI_PROMPT} {entry["content"]}\n\n'
        prompt += AI_PROMPT
        return prompt

    # Remove system messages if it is a demonstration
    if is_demonstration:
        history = [entry for entry in history if entry["role"] != "system"]
        return "\n".join([entry["content"] for entry in history])

    # Return history components with just role, content fields (no system message)
    messages = [
        {k: v for k, v in entry.items() if k in ["role", "content"]} for entry in history if entry["role"] != "system"
    ]
    compiled_messages = []  # Combine messages from the same role
    last_role = None
    for message in reversed(messages):
        if last_role == message["role"]:
            compiled_messages[-1]["content"] = message["content"] + "\n" + compiled_messages[-1]["content"]
        else:
            compiled_messages.append(message)
        last_role = message["role"]
    compiled_messages = list(reversed(compiled_messages))
    # Replace any empty content values with a "(No output)"
    for message in compiled_messages:
        if message["content"].strip() == "":
            message["content"] = "(No output)"
    return compiled_messages


def anthropic_query(model: AnthropicModel | BedrockModel, history: list[dict[str, str]]) -> str:
    """
    Query the Anthropic API with the given `history` and return the response.
    """
    # Preserve behavior for older models
    if model.api_model in ["claude-instant", "claude-2.0", "claude-2.1"] or (
        isinstance(model, BedrockModel) and model.model_provider == "anthropic" and model.api_model in ["anthropic.claude-instant-v1", "anthropic.claude-v2"]
    ):
        # Perform Anthropic API call
        prompt = anthropic_history_to_messages(model, history)
        if isinstance(model, BedrockModel):
            # Use a dummy Anthropic client since count_tokens
            # is not available in AnthropicBedrock
            # https://github.com/anthropics/anthropic-sdk-python/issues/353
            input_tokens = Anthropic().count_tokens(prompt)
        else:
            input_tokens = model.api.count_tokens(prompt)
        completion = model.api.completions.create(
            model=model.api_model,
            prompt=prompt,
            max_tokens_to_sample=model.model_metadata["max_context"] - input_tokens
            if isinstance(model, Anthropic)
            else model.model_metadata["max_tokens_to_sample"],
            temperature=model.args.temperature,
            top_p=model.args.top_p,
            top_k=model.args.top_k,
        )
        # Calculate + update costs, return response
        response = completion.completion
        if isinstance(model, BedrockModel):
            output_tokens = Anthropic().count_tokens(response)
        else:
            output_tokens = model.api.count_tokens(response)
        model.update_stats(input_tokens, output_tokens)
        return response

    # Get system message(s)
    system_message = "\n".join([entry["content"] for entry in history if entry["role"] == "system"])
    messages = anthropic_history_to_messages(model, history)

    # Perform Anthropic API call
    response = model.api.messages.create(
        messages=messages,
        max_tokens=model.model_metadata["max_tokens"],
        model=model.api_model,
        temperature=model.args.temperature,
        top_p=model.args.top_p,
        system=system_message,
    )
    # Calculate + update costs, return response
    model.update_stats(response.usage.input_tokens, response.usage.output_tokens)
    response_text = "\n".join([x.text for x in response.content]).split("(Open file:")[0].strip()
    print(messages)
    print(response_text)
    return response_text


def get_model(args: ModelArguments, commands: list[Command] | None = None):
    """
    Returns correct model object given arguments and commands
    """
    if commands is None:
        commands = []
    
    # Load configurations to check shortcuts
    configs = load_model_configs()
    
    # Special models first
    if args.model_name == "instant_empty_submit":
        return InstantEmptySubmitTestModel(args, commands)
    if args.model_name == "human":
        return HumanModel(args, commands)
    if args.model_name == "human_thought":
        return HumanThoughtModel(args, commands)
    if args.model_name == "replay":
        return ReplayModel(args, commands)
    
    # Check model prefixes
    if (args.model_name.startswith("gpt") or 
        args.model_name.startswith("ft:gpt") or 
        args.model_name.startswith("azure:gpt") or 
        args.model_name.startswith("o1") or
        args.model_name.startswith("deepseek-r") or
        args.model_name in configs.get('openai_shortcuts', {}) or
        args.model_name in configs.get('openai_models', {})):
        return OpenAIModel(args, commands)
    elif args.model_name.startswith("claude") or args.model_name in configs.get('anthropic_shortcuts', {}):
        return AnthropicModel(args, commands)
    elif args.model_name.startswith("bedrock"):
        return BedrockModel(args, commands)
    elif args.model_name.startswith("ollama"):
        return OllamaModel(args, commands)
    elif args.model_name.startswith("deepseek") and not args.model_name.startswith("deepseek-r"):
        return DeepSeekModel(args, commands)
    elif (args.model_name.startswith("groq") or 
          args.model_name in configs.get('groq_shortcuts', {}) or
          args.model_name in configs.get('groq_models', {})):
        return GroqModel(args, commands)
    elif args.model_name in configs.get('together_shortcuts', {}) or args.model_name in configs.get('together_models', {}):
        return TogetherModel(args, commands)
    elif args.model_name.startswith("vllm:"):
        return VLLMModel(args, commands)
    else:
        # Try to determine model type from configurations
        if args.model_name in configs.get('openai_models', {}):
            return OpenAIModel(args, commands)
        elif args.model_name in configs.get('anthropic_models', {}):
            return AnthropicModel(args, commands)
        elif args.model_name in configs.get('groq_models', {}):
            return GroqModel(args, commands)
        elif args.model_name in configs.get('together_models', {}):
            return TogetherModel(args, commands)
        elif args.model_name in configs.get('deepseek_models', {}):
            return DeepSeekModel(args, commands)
        elif args.model_name in configs.get('special_models', {}):
            # Default to OpenAI-compatible for unknown special models
            return OpenAIModel(args, commands)
        else:
            # Default to OpenAI model for unknown models (with warning in BaseModel)
            return OpenAIModel(args, commands)
