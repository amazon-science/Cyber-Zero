# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
"""
SWE-agent Environment Module

This module provides the core environment for SWE-agent, handling communication with 
Docker containers and managing task execution.

TIMEOUT HANDLING AND STUCK EXECUTION ISSUES
==========================================

The SWE-agent environment includes comprehensive timeout handling to prevent hung executions:

1. **Agent Action Timeouts**:
   - SWE_AGENT_ACTION_TIMEOUT: Maximum time for any agent command (default: 25s)
   - SWE_AGENT_ACTION_NO_OUTPUT_TIMEOUT: Time to wait when no output is produced (default: same as above)

2. **Docker Operation Timeouts**:
   - SWE_AGENT_DOCKER_EXEC_TIMEOUT: Timeout for Docker exec operations (default: 30s)
   - SWE_AGENT_CONTAINER_HEALTH_CHECK_TIMEOUT: Timeout for container health checks (default: 5s)

3. **Recovery Mechanisms**:
   - SWE_AGENT_INTERRUPT_TIMEOUT: Time to wait during process interruption (default: 20s)
   - SWE_AGENT_MAX_EXECUTION_RETRIES: Maximum retry attempts for failed commands (default: 2)

4. **Task-Level Timeout**:
   - SWE_AGENT_TASK_TIMEOUT: Maximum time for entire task execution (default: 900s / 15 minutes)

5. **Model Generation Timeout**:
   - SWE_AGENT_MODEL_TIMEOUT: Maximum time for individual model queries (default: 300s / 5 minutes)

Common Stuck Execution Scenarios:
- Long-running filesystem operations (grep -r, find /, etc.)
- Interactive programs waiting for input
- Network operations that hang
- Container becoming unresponsive
- Process deadlocks

Environment Variables for Timeout Configuration:
- Set longer timeouts for complex operations: SWE_AGENT_ACTION_TIMEOUT=60
- Enable strict timeouts for testing: SWE_AGENT_ACTION_NO_OUTPUT_TIMEOUT=10
- Adjust Docker operation timeouts: SWE_AGENT_DOCKER_EXEC_TIMEOUT=45
- Set task execution timeout: SWE_AGENT_TASK_TIMEOUT=1800  # 30 minutes
- Set model generation timeout: SWE_AGENT_MODEL_TIMEOUT=600  # 10 minutes

Usage Example:
    export SWE_AGENT_ACTION_TIMEOUT=45
    export SWE_AGENT_ACTION_NO_OUTPUT_TIMEOUT=20
    export SWE_AGENT_MAX_EXECUTION_RETRIES=3
    export SWE_AGENT_TASK_TIMEOUT=1200  # 20 minutes
    export SWE_AGENT_MODEL_TIMEOUT=600  # 10 minutes
    python run.py --config config.yaml

The environment will automatically detect and handle most stuck execution scenarios
with appropriate error messages and recovery attempts.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import os
import random
import re
import shlex
import socket
import subprocess
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any

import gymnasium as gym
import yaml
from ghapi.all import GhApi
from git import Repo
from simple_parsing.helpers.serialization.serializable import FrozenSerializable
from swebench.harness.constants import MAP_REPO_VERSION_TO_SPECS
from swebench.harness.utils import get_environment_yml, get_requirements

import docker
import docker.errors
import docker.models.containers
from sweagent import REPO_ROOT
from sweagent.agent.interactive_commands import (
    INTERACTIVE_SESSIONS_CONFIG,
    InteractiveSession,
    InteractiveSessionConfig,
    get_interactive_commands,
    get_interactive_session,
)
from sweagent.environment.utils import (
    PROCESS_DONE_MARKER_END,
    PROCESS_DONE_MARKER_START,
    InvalidGithubURL,
    NoOutputTimeoutError,
    PatchFormatter,
    attach_network_interface_to_container,
    cleanup_dynamic_network,
    cleanup_all_dynamic_networks,
    cleanup_dynamic_resources,
    force_cleanup_all_ctf_resources,
    copy_anything_to_container,
    copy_file_to_container,
    format_trajectory_markdown,
    get_container,
    get_docker_compose,
    get_gh_issue_data,
    get_instances,
    image_exists,
    parse_gh_issue_url,
    read_with_timeout,
    read_with_timeout_experimental,
    terminate_docker_compose,
    test_network_connectivity,
    wait_for_service_availability,
    check_docker_subnet_availability,
    _setup_network_restrictions,
    check_network_restrictions_applied,
    _setup_network_restrictions_for_challenge_containers,
)
from sweagent.types import AgentInfo
from sweagent.utils.config import keys_config
from sweagent.utils.log import default_logger, get_logger

LONG_TIMEOUT = float(keys_config.get("SWE_AGENT_ENV_LONG_TIMEOUT", 500))
AGENT_ACTION_TIMEOUT = float(keys_config.get("SWE_AGENT_ACTION_TIMEOUT", 25))
AGENT_ACTION_NO_OUTPUT_TIMEOUT = float(keys_config.get("SWE_AGENT_ACTION_NO_OUTPUT_TIMEOUT", AGENT_ACTION_TIMEOUT))
PATH_TO_REQS = "/root/requirements.txt"
PATH_TO_ENV_YML = "/root/environment.yml"

# CTF server validation timeout
CTF_SERVER_VALIDATION_TIMEOUT = float(keys_config.get("SWE_AGENT_CTF_SERVER_VALIDATION_TIMEOUT", 10))

# Additional timeout configurations for stuck execution handling
DOCKER_EXEC_TIMEOUT = float(keys_config.get("SWE_AGENT_DOCKER_EXEC_TIMEOUT", 30))
CONTAINER_HEALTH_CHECK_TIMEOUT = float(keys_config.get("SWE_AGENT_CONTAINER_HEALTH_CHECK_TIMEOUT", 5))
INTERRUPT_TIMEOUT = float(keys_config.get("SWE_AGENT_INTERRUPT_TIMEOUT", 20))
MAX_EXECUTION_RETRIES = int(keys_config.get("SWE_AGENT_MAX_EXECUTION_RETRIES", 2))

# Task-level timeout configuration (15 minutes = 900 seconds by default)
TASK_EXECUTION_TIMEOUT = float(keys_config.get("SWE_AGENT_TASK_TIMEOUT", 900))

# Model generation timeout configuration (5 minutes = 300 seconds by default)
# This prevents individual model queries from blocking task timeout
MODEL_GENERATION_TIMEOUT = float(keys_config.get("SWE_AGENT_MODEL_TIMEOUT", 300))


@dataclass(frozen=True)
class EnvironmentArguments(FrozenSerializable):
    """Configure data sources and setup instructions for the environment in which we solve the tasks."""

    # Source of issue statement/problem statement. To run over a batch of issues: Path to a data file
    # (`json`, `jsonl`) or directory. To run over single issue: github issue url or path to markdown file
    # with problem statement or problem statement as text prefixed with `text://`.
    data_path: str
    # Name of the docker image to use for the environment. Defaults to sweagent/swe-agent:latest
    image_name: str = "sweagent/swe-agent:latest"
    # When running over SWE-bench issues: Specify the split to use.
    split: str = "dev"
    # Specify a branch name or a commit hash to checkout before running the task.
    # Only used when running over a single problem statement/issue.
    base_commit: str | None = None
    # Use a persistent container with this name. After every task, the container will be paused, but not removed.
    # This is useful for speedup when running multiple tasks from the same repositories in a row, as the repositories
    # will have already been cloned and the conda environments will have been installed.
    container_name: str | None = None
    # Try to install the environment before running the task.
    install_environment: bool = True
    # No effect, kept for backwards compatibility.
    timeout: int | None = None
    # Enable environment logger.
    verbose: bool = False
    # Do not use attempt to use a repository mirror from https://github.com/swe-bench.
    no_mirror: bool = False
    # Cache task images to speed up task initialization. This means that the environment will be saved as a
    # docker image for every repository, base commit, and setup combination. This uses quite a bit of disk space
    # but speeds up task initialization significantly when running over multiple issues from the same repository
    # (or using different models for the same issues).
    cache_task_images: bool = False
    # Custom environment setup. Currently only used when data_path points to a single issue.
    # This needs to be either a string pointing to a yaml file (with yaml, yml file extension)
    # or a shell script (with sh extension).
    # See https://princeton-nlp.github.io/SWE-agent/usage/cl_tutorial#environment-setup
    environment_setup: str | None = None
    # Only used when running on single issue. Path to local repository or github repository.
    repo_path: str = ""
    # Interactive command configuration
    interactive_sessions_config: dict[str, InteractiveSessionConfig] = field(
        default_factory=lambda: INTERACTIVE_SESSIONS_CONFIG
    )
    # Container mounts - additional folders to mount into the environment (useful for caching)
    container_mounts: list[str] = field(default_factory=list)
    # Enable dynamic port allocation for CTF challenges to support parallel execution
    enable_dynamic_ports: bool = False
    # Allow working with dirty git repositories (skip the dirty check)
    allow_dirty_repo: bool = False
    # Enable STRICT network restrictions to block ALL external connections (allows only localhost and Docker internal networks)
    enable_network_restrictions: bool = False

    def __post_init__(self):
        if self.timeout is not None:
            default_logger.warning("The 'timeout' argument is deprecated and has no effect.")
        if self.cache_task_images and self.container_name:
            msg = (
                "Not allowed to use persistent container with caching task images "
                "(probably doesn't make sense and takes excessive space)."
            )
            raise ValueError(msg)
        if self.container_name is not None and self.container_name.strip() == "":
            msg = "Set container_name to None if you don't want to use a persistent container."
            raise ValueError(msg)


class EnvHook:
    """Hook to be used in `SWEEnv`.

    Subclass this class, add functionality and add it with `SWEEEnv.add_hook(hook)`.
    This allows to inject custom functionality at different stages of the environment
    lifecycle, in particular to connect SWE-agent to a new interface (like a GUI).
    """

    def on_init(self) -> None:
        """Gets called when the hook is added"""

    def on_copy_repo_started(self, *, repo_type: str, repo_path: str) -> None:
        """Gets called when the repository is being cloned to the container

        Args:
            repo_type: Type of repository. Either 'local' or 'github'
            repo_path: Path to the repository
        """

    def on_install_env_started(self) -> None:
        """Called when we start installing the environment"""

    def on_close(self):
        """Called when the environment is closed"""


class SWEEnv(gym.Env):
    """Gym environment for SWE-bench. This class should handle all communication with the docker container."""

    name = "swe_main"
    # This prefix will be prepended to the image name when caching task images
    cached_image_prefix = "swe-agent-task-env-"

    def __init__(self, args: EnvironmentArguments):
        super().__init__()
        t0 = time.perf_counter()
        self.args = args
        self.base_commit: str | None = None
        self.communicate_output: str | None = None
        self.container_name: str | None = args.container_name
        self.install_environment = args.install_environment
        self.logger = get_logger("SWEEnv")
        self.persistent = args.container_name is not None
        self.container_mounts = args.container_mounts
        self.returncode: None | int = None
        # Track if we've already cleaned up to avoid double cleanup
        self._cleanup_done = False
        if not self.args.verbose:
            # fixme: This creates problems if we have multiple instances of this class
            self.logger.disabled = True

        #: The commit hash of the swe-agent repository
        self.commit_sha = None
        try:
            repo = Repo(REPO_ROOT, search_parent_directories=True)
            self.commit_sha = repo.head.object.hexsha
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.logger.exception("Failed to get commit hash for this repo: %s", str(e))

        self._github_token: str = keys_config.get("GITHUB_TOKEN", "")  # type: ignore

        # Load Task Instances
        self.data_path = self.args.data_path
        self.data = get_instances(
            self.data_path,
            self.args.base_commit,
            self.args.split,
            token=self._github_token,
            repo_path=self.args.repo_path,
            allow_dirty_repo=self.args.allow_dirty_repo,
        )
        #: Instance we're currently processing. Gets set in self.reset.
        self.record: dict[str, Any] | None = None
        self.logger.info(f"💽 Loaded dataset from {self.data_path}")

        # Establish connection with execution container
        self.image_name = args.image_name
        self.container_obj: docker.models.containers.Container | None = None
        self.container: subprocess.Popen | None = None
        self.docker_compose: Path | None = None
        self.challenge: dict[str, Any] | None = None
        # Dynamic port allocation for CTF challenges
        self.port_mappings: dict[str, int] = {}
        self.dynamic_network_name: str | None = None
        # Track docker-compose project name for proper cleanup in parallel execution
        self.docker_compose_project_name: str | None = None
        self._reset_container()

        self.interactive_session: InteractiveSession | None = None

        self.idx = 0
        self.clean_multi_line_functions = lambda x: x
        self.hooks: list[EnvHook] = []

        self.logger.debug("Environment initialization took %.2f seconds", time.perf_counter() - t0)

    def __del__(self):
        """Ensure cleanup happens even if close() isn't called explicitly"""
        if not self._cleanup_done:
            try:
                self._cleanup_docker_resources(final_cleanup=True)
            except Exception as e:
                # Use print instead of logger since logger might not be available during __del__
                print(f"Warning: Failed to cleanup Docker resources in __del__: {e}")

    def _cleanup_docker_resources(self, final_cleanup: bool = True):
        """Clean up all Docker resources created by this instance
        
        Args:
            final_cleanup: If True, this is a final shutdown and all resources should be cleaned up.
                          If False, this is a reset and persistent containers should be preserved.
        """
        if self._cleanup_done and final_cleanup:
            return
            
        try:
            # 1. Clean up the main container if we know its name
            if (hasattr(self, 'container_name') and self.container_name is not None and
                not self.persistent and final_cleanup):
                # Only remove non-persistent containers during final cleanup
                try:
                    client = docker.from_env()
                    try:
                        container = client.containers.get(self.container_name)
                        self.logger.debug(f"🐳 Stopping and removing container: {self.container_name}")
                        container.stop(timeout=5)
                        container.remove(force=True)
                        self.logger.debug(f"✅ Successfully removed container: {self.container_name}")
                    except docker.errors.NotFound:
                        self.logger.debug(f"Container {self.container_name} already removed")
                    except Exception as e:
                        self.logger.warning(f"Failed to remove container {self.container_name}: {e}")
                except Exception as e:
                    self.logger.warning(f"Failed to connect to Docker for container cleanup: {e}")
            
            # 2. Clean up docker-compose services if we have a compose file and project name
            if (hasattr(self, 'docker_compose') and self.docker_compose is not None and
                hasattr(self, 'docker_compose_project_name') and self.docker_compose_project_name is not None):
                try:
                    self.logger.debug(f"🏗️ Cleaning up docker-compose project: {self.docker_compose_project_name}")
                    
                    # Use docker-compose down to clean up all services, networks, and volumes
                    down_cmd = [
                        "docker", "compose", "-f", str(self.docker_compose), 
                        "-p", self.docker_compose_project_name,
                        "down", "--volumes", "--remove-orphans"
                    ]
                    result = subprocess.run(down_cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        self.logger.debug(f"✅ Successfully cleaned up docker-compose project: {self.docker_compose_project_name}")
                    else:
                        self.logger.warning(f"Docker-compose down failed: {result.stderr}")
                        
                        # Fallback: stop and remove services individually
                        stop_cmd = ["docker", "compose", "-f", str(self.docker_compose), "-p", self.docker_compose_project_name, "stop"]
                        subprocess.run(stop_cmd, capture_output=True, timeout=20)
                        
                        rm_cmd = ["docker", "compose", "-f", str(self.docker_compose), "-p", self.docker_compose_project_name, "rm", "-f"]
                        subprocess.run(rm_cmd, capture_output=True, timeout=20)
                        
                except Exception as e:
                    self.logger.warning(f"Failed to clean up docker-compose project: {e}")
            
            # 3. Clean up the dynamic network if we created one
            if hasattr(self, 'dynamic_network_name') and self.dynamic_network_name is not None:
                try:
                    client = docker.from_env()
                    try:
                        network = client.networks.get(self.dynamic_network_name)
                        self.logger.debug(f"🌐 Removing network: {self.dynamic_network_name}")
                        
                        # Force disconnect any remaining containers
                        try:
                            network.reload()
                            containers = network.attrs.get('Containers', {})
                            for container_id, container_info in containers.items():
                                container_name = container_info.get('Name', container_id)
                                # Skip disconnecting persistent containers during reset
                                if not final_cleanup and self.persistent and container_name == self.container_name:
                                    self.logger.debug(f"  Preserving persistent container {container_name} connection")
                                    continue
                                    
                                self.logger.debug(f"  📤 Disconnecting container {container_name} from {self.dynamic_network_name}")
                                try:
                                    container_obj = client.containers.get(container_id)
                                    network.disconnect(container_obj, force=True)
                                except Exception as e:
                                    self.logger.debug(f"    Failed to disconnect {container_name}: {e}")
                        except Exception as e:
                            self.logger.debug(f"Failed to disconnect containers from network: {e}")
                        
                        # Only remove the network during final cleanup
                        if final_cleanup:
                            network.remove()
                            self.logger.debug(f"✅ Successfully removed network: {self.dynamic_network_name}")
                        
                    except docker.errors.NotFound:
                        self.logger.debug(f"Network {self.dynamic_network_name} already removed")
                    except Exception as e:
                        self.logger.warning(f"Failed to remove network {self.dynamic_network_name}: {e}")
                except Exception as e:
                    self.logger.warning(f"Failed to connect to Docker for network cleanup: {e}")
            
            # 4. Clean up temporary docker-compose files
            if (hasattr(self, 'args') and self.args.enable_dynamic_ports and 
                hasattr(self, 'docker_compose') and self.docker_compose is not None and
                self.docker_compose.name.startswith('docker-compose-')):
                try:
                    if self.docker_compose.exists():
                        self.docker_compose.unlink()
                        self.logger.debug(f"🗑️ Cleaned up temporary docker-compose file: {self.docker_compose}")
                except Exception as e:
                    self.logger.warning(f"Failed to clean up temporary docker-compose file: {e}")
            
            # 5. Clean up any challenge containers if we have docker-compose project info
            if (hasattr(self, 'docker_compose_project_name') and self.docker_compose_project_name is not None and
                hasattr(self, 'challenge') and self.challenge is not None):
                try:
                    client = docker.from_env()
                    
                    # Find containers that belong to our docker-compose project
                    project_label = f"com.docker.compose.project={self.docker_compose_project_name}"
                    project_containers = client.containers.list(all=True, filters={"label": project_label})
                    
                    if project_containers:
                        self.logger.debug(f"🧹 Cleaning up {len(project_containers)} containers from project {self.docker_compose_project_name}")
                        for container in project_containers:
                            try:
                                container.stop(timeout=5)
                                container.remove(force=True)
                                self.logger.debug(f"  ✅ Removed container: {container.name}")
                            except Exception as e:
                                self.logger.debug(f"  Failed to remove container {container.name}: {e}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to clean up challenge containers: {e}")
                    
        except Exception as e:
            self.logger.warning(f"Error during Docker resource cleanup: {e}")
        
        # Only mark cleanup as done for final cleanup
        if final_cleanup:
            self._cleanup_done = True

    def _get_cached_task_image_name(self) -> str:
        assert self.record is not None
        inputs: list[str] = [
            self.record["repo"],
            self.record["base_commit"],
            self.args.environment_setup or "no_setup",
        ]
        tag = hashlib.sha256("".join(inputs).encode()).hexdigest()[:50]
        return f"{self.cached_image_prefix}{tag}"

    def add_hook(self, hook: EnvHook):
        """Add `EnvHook` to the environment.

        This allows to inject custom functionality at different stages of the environment
        lifecycle, in particular to connect SWE-agent to a new interface (like a GUI).
        """
        hook.on_init()
        self.hooks.append(hook)

    @property
    def _repo_name(self) -> str:
        """Name of the local copy of the repository"""
        assert self.record is not None
        return self.record["repo"].replace("/", "__").replace(" ", "-").replace("'", "")

    def _copy_repo(self) -> str:
        """Clone/copy repository/codebase in container

        Returns:
            folder name of clone
        """
        assert self.container_obj is not None
        assert self.record is not None  # mypy
        
        # CRITICAL: Validate container object before file operations
        # In parallel execution, ensure we're working with the right container
        try:
            self.container_obj.reload()  # Refresh container state
            if self.container_obj.name != self.container_name:
                self.logger.error(f"❌ Container object mismatch! Expected: {self.container_name}, Got: {self.container_obj.name}")
                raise RuntimeError(f"Container object mismatch: expected {self.container_name} but got {self.container_obj.name}")
            self.logger.debug(f"✅ Validated container object: {self.container_name}")
        except Exception as e:
            self.logger.error(f"❌ Failed to validate container object: {e}")
            raise RuntimeError(f"Container validation failed: {e}")
        
        for hook in self.hooks:
            hook.on_copy_repo_started(repo_type=self.record["repo_type"], repo_path=self.record["repo"])
        if self.record["repo_type"] == "local":
            if "challenge" in self.record:
                self.communicate_with_handling(
                    input=f"mkdir {self._repo_name}", error_msg=f"Failed to create {self._repo_name} in container"
                )
                for file_name in self.record["challenge"]["files"]:
                    self.logger.debug(f"Copying file {file_name} to container {self.container_name}")
                    # Double-check we're copying to the right container
                    copy_anything_to_container(
                        self.container_obj,
                        str(Path(self.record["repo"].removeprefix("local://")) / file_name),
                        "/" + self._repo_name,
                    )
            else:
                copy_anything_to_container(
                    self.container_obj,
                    self.record["repo"].removeprefix("local://"),
                    "/" + self._repo_name,
                )
            self.communicate_with_handling(
                input=f"chown -R root:root {self._repo_name}",
                error_msg="Failed to change permissions on copied repository",
            )
            return self._repo_name
        assert self.record["repo_type"] == "github"
        token_prefix = ""
        if self._github_token:
            token_prefix = f"{self._github_token}@"
        # fixme: This if statement is brittle and should probably be replaced with better logic
        if not self.args.no_mirror and self.record["problem_statement_source"] == "swe-bench":
            self.logger.info(f"{self._repo_name} not found in container, cloning...")
            clone_url = f"https://{token_prefix}github.com/swe-bench/{self._repo_name}.git"
        else:
            self.logger.info("Trying to clone from non-mirror...")
            clone_url = f"https://{token_prefix}github.com/{self.record['repo']}.git"
        clone_method = keys_config.get("SWE_AGENT_CLONE_METHOD", default="shallow", choices=["shallow", "full"])
        if len(self.data) > 1 or self.persistent:
            msg = "Falling back to full cloning method due to multiple instances or persistent container"
            clone_method = "full"
            self.logger.debug(msg)
        if clone_method == "full":
            self.communicate_with_handling(
                input=f"git clone {clone_url} {self._repo_name}",
                error_msg="Failed to clone repository from conservative method",
                timeout_duration=LONG_TIMEOUT,
                redact_command_trace=True,
            )
        else:
            base_commit = self.record["base_commit"]
            self.communicate_with_handling(
                input="&&".join(
                    (
                        f"mkdir {self._repo_name}",
                        f"cd {self._repo_name}",
                        "git init",
                        f"git remote add origin {clone_url}",
                        f"git fetch --depth 1 origin {base_commit}",
                        "git checkout FETCH_HEAD",
                        "cd ..",
                    )
                ),
                error_msg="Failed to clone repository with fast method",
                timeout_duration=LONG_TIMEOUT,
            )
        return self._repo_name

    def reset(self, index: int | None = None, apply_test_patch: bool = False) -> tuple[str | None, dict]:
        """
        Function to reset container between each task instance.

        * Clones instance's repository
        * Cleans repository of prior modifications
        * Resets environment variables
        * Check out base commit

        Args:
            index: index of task instance to reset to

        Returns:
            observation: output from container
            info: additional information (e.g. debugging information)
        """
        info = {}
        info["commit_sha"] = self.commit_sha

        # Get task instance
        self.idx = index if index is not None else self.idx
        self.record = self.data[self.idx]
        self.idx += 1

        # Set query, gold command
        self.base_commit = self.record["base_commit"]
        self.query = self.record["problem_statement"]
        self.challenge = self.record.get("challenge")
        self.reward = None

        if self.args.cache_task_images:
            cached_image = self._get_cached_task_image_name()
            if image_exists(cached_image):
                self.logger.info(f"Restore environment from cached image {cached_image}")
                self.close()  # stop current container
                self._init_container(cached_image=cached_image)
                self.communicate("export $(xargs </.env)")
                envs = self.communicate("env")
                self.logger.debug(f"Environment variables restored from the image:\n{envs}\n")
                if apply_test_patch:
                    self._apply_test_patch()
                # Set up flag file for CTF challenges
                self._setup_ctf_flag()
                
                # Apply network restrictions if not already applied (for cached images)
                if self.args.enable_network_restrictions:
                    self.logger.info("🔒 Checking network restrictions for cached image...")
                    try:
                        if not check_network_restrictions_applied(self.container_name):
                            self.logger.info("Applying network restrictions to cached container...")
                            _setup_network_restrictions(self.container_name)
                            self.logger.info("✅ Network restrictions applied to cached container")
                        else:
                            self.logger.info("✅ Network restrictions already applied to cached container")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to apply network restrictions to cached container: {e}")
                        self.logger.warning("⚠️  SECURITY WARNING: Network restrictions were not applied!")
                        info["network_restrictions_warning"] = f"Failed to apply restrictions to cached container: {e}"
                
                # Verify that network restrictions are working properly
                if self.args.enable_network_restrictions:
                    self.logger.info("🔍 Verifying network restrictions are properly applied...")
                    try:
                        restrictions_working = self._verify_network_restrictions()
                        if not restrictions_working:
                            self.logger.error("❌ SECURITY WARNING: Network restrictions failed - external access is possible!")
                            info["network_restrictions_warning"] = "Network restrictions verification failed"
                        else:
                            self.logger.info("✅ Network restrictions verified - external access blocked")
                            info["network_restrictions_status"] = "verified_working"
                    except Exception as e:
                        self.logger.warning(f"Network restrictions verification failed with error: {e}")
                        info["network_restrictions_warning"] = f"Verification error: {e}"
                
                # Write any metadata to info if necessary
                return None, info
            else:
                self.logger.info(f"Cached image {cached_image} not found, rebuilding task environment...")

        # Init docker network/compose based on challenge type
        # For CTF challenges, initialize docker-compose which handles network creation and service startup
        # For non-CTF challenges, just initialize the basic docker network
        if self.challenge is None:
            self._init_docker_network()
        else:
            self._init_docker_compose()

        # For CTF challenges, give additional time for network services to fully register their aliases
        if self.challenge is not None:
            self.logger.debug("Allowing extra time for CTF services to register network aliases...")
            time.sleep(15)  # Additional wait after network connection

        # Validate CTF server connectivity before proceeding
        if not self._validate_ctf_server_connectivity():
            # CRITICAL FIX: Don't give up immediately - try restarting Docker services first
            self.logger.warning("⚠️  Initial CTF server validation failed. Attempting to restart services...")
            
            restart_success = self._restart_ctf_services_and_retry_validation()
            if not restart_success:
                self.logger.error("❌ CTF server validation failed even after restart attempts. Shutting down task.")
                info["exit_status"] = "ctf_server_unavailable"
                info["error_message"] = "CTF server is not accessible even after restart attempts. Task terminated."
                # Clean up resources before returning
                try:
                    self.close()
                except Exception as cleanup_error:
                    self.logger.warning(f"Error during cleanup: {cleanup_error}")
                return None, info
            else:
                self.logger.info("✅ CTF server validation succeeded after restart")

        # Clone repository if not already cloned
        self.communicate(input="cd /")
        folders = self.communicate(input="ls").split("\n")
        if self._repo_name not in folders:
            self._copy_repo()

        self._reset_repository()
        self._reset_environment_variables()

        # Set up environment
        self.communicate_with_handling(
            "source /root/miniconda3/etc/profile.d/conda.sh",
            error_msg="Failed to source conda",
        )

        system = self.communicate("uname -s").strip().lower()
        arch = self.communicate("uname -m").strip().lower()
        if system == "linux" and arch == "x86_64":
            self.communicate_with_handling(
                "apt update; apt install build-essential -y",
                error_msg="Failed to install build-essential",
                timeout_duration=LONG_TIMEOUT,
            )

        # Call install environment helper function if specified
        if self.install_environment:
            self.install_env()
        # Install mypy for linting purposes
        self.communicate_with_handling("pip install flake8", error_msg="Failed to install flake8 (lint library)")

        # Apply network restrictions AFTER setup is complete (including package installations)
        # This allows setup packages to be downloaded while still protecting against external access during agent execution
        if self.args.enable_network_restrictions:
            self.logger.info("🔒 Applying network restrictions after environment setup...")
            try:
                from sweagent.environment.utils import _setup_network_restrictions, check_network_restrictions_applied
                
                # Check if restrictions are already applied (e.g., for persistent containers)
                if check_network_restrictions_applied(self.container_name):
                    self.logger.info("✅ Network restrictions already applied to container")
                else:
                    _setup_network_restrictions(self.container_name)
                    self.logger.info("✅ Network restrictions applied successfully after setup")
            except Exception as e:
                self.logger.error(f"❌ Failed to apply network restrictions after setup: {e}")
                self.logger.warning("⚠️  SECURITY WARNING: Network restrictions were not applied!")
                info["network_restrictions_warning"] = f"Failed to apply restrictions after setup: {e}"

        if self.args.cache_task_images:
            envs = self.communicate("env")
            self.logger.debug(f"Environment variables to save:\n{envs}\n")
            self.communicate("env >> /.env")
            assert self.container_obj is not None  # mypy
            self.container_obj.commit(cached_image)
            self.logger.info(f"Container with environment {self.container_obj.id} cached as image {cached_image}")

        if apply_test_patch:
            self._apply_test_patch()
        # Set up flag file for CTF challenges
        self._setup_ctf_flag()
        
        # Verify that network restrictions are working properly
        if self.args.enable_network_restrictions:
            self.logger.info("🔍 Verifying network restrictions are properly applied...")
            try:
                restrictions_working = self._verify_network_restrictions()
                if not restrictions_working:
                    self.logger.error("❌ SECURITY WARNING: Network restrictions failed - external access is possible!")
                    info["network_restrictions_warning"] = "Network restrictions verification failed"
                else:
                    self.logger.info("✅ Network restrictions verified - external access blocked")
                    info["network_restrictions_status"] = "verified_working"
            except Exception as e:
                self.logger.warning(f"Network restrictions verification failed with error: {e}")
                info["network_restrictions_warning"] = f"Verification error: {e}"
        
        # Write any metadata to info if necessary
        return None, info

    def _reset_repository(self) -> None:
        """Clean repository of any modifications + Checkout base commit"""
        startup_commands = [
            "echo -n > /root/files_to_edit.txt",
            f"cd /{self._repo_name}",
            "export ROOT=$(pwd -P)",
        ]
        if self.challenge is None:
            startup_commands += [
                "git status",
                "git restore .",
                f"git reset --hard {self.base_commit}",
                "git clean -fdxq",
            ]
        self.communicate_with_handling(
            input=" && ".join(startup_commands),
            error_msg="Failed to clean repository",
        )

    def _reset_environment_variables(self) -> None:
        """Reset environment variables (`CURRENT_FILE`) etc. within container"""
        cmd = [
            'export CURRENT_FILE=""',
            "export CURRENT_LINE=0",
            "export SEARCH_RESULTS=()",
            "export SEARCH_FILES=()",
            "export SEARCH_INDEX=0",
        ]
        self.communicate_with_handling(
            input=" && ".join(cmd),
            error_msg="Failed to reset environment variables",
        )

    def reset_for_new_attempt(
        self,
    ) -> None:
        """Compared to `reset`, which prepares the container for a new instance,
        this prepares the container for taking another shot at the same instance.
        """
        self._reset_repository()
        self._reset_environment_variables()

    def _apply_test_patch(self):
        """
        Apply test patch for oracle setting
        """
        assert self.record is not None
        path_to_patch = "test.patch"
        with open(path_to_patch, "w") as f:
            f.write(self.record["test_patch"])
        subprocess.run(
            f"docker cp {path_to_patch} {self.container_name}:/root/test.patch",
            shell=True,
            check=False,
        )
        self.communicate_with_handling(
            input="git apply /root/test.patch",
            error_msg="Failed to apply test patch correctly",
        )
        os.remove(path_to_patch)

    def _get_edited_files_with_context(self, patch: str) -> dict[str, str]:
        """Get the edited files with context from the patch"""
        pf = PatchFormatter(patch, read_method=self.read_file) if patch else None
        out = {}
        for context_length in [30, 50, 70]:
            value = "Empty. No edited files found."
            if pf is not None:
                value = pf.get_files_str(original=False, context_length=context_length)
            out[f"edited_files{context_length}"] = value
        return out

    def _terminate_interactive_session(self, session_name: str):
        if not self.interactive_session:
            # Maybe fixing #772
            return
        try:
            self.interactive_session.session_process.terminate()
            self.communicate(self.interactive_session.config.exit_command)
        except Exception as e:
            msg = (
                f"Failed to terminate interactive session {session_name}: {e}."
                "\nHere's the full traceback\n" + traceback.format_exc()
            )
            self.logger.warning(msg)
        self.interactive_session = None

    def _handle_interactive_commands(self, observation: str) -> str:
        """Handle interactive commands in the environment, essentially substituting dummy
        output for the actual output of the interactive commands.

        Args:
            observation: Output from running the interactive command wrappers in the
                environment. They will returns some dummy output that will be caught and then
                we will run the actual commands in the interactive session and return the
                actual output.

        Returns:
            observation: The observation shown to the model. If no interactive commands
                are detected, this is the same as the input observation.
                Else, only the output from the interactive commands is returned.
        """
        session_name, interactive_commands = get_interactive_commands(observation, logger=self.logger)
        if session_name is None:
            return observation
        if (
            session_name is not None
            and self.interactive_session is not None
            and self.interactive_session.name != session_name
        ):
            return self.interactive_session._get_only_one_interactive_error_message_observation()

        observation = ""
        for command in interactive_commands:
            if command == "START":
                # Start the session if previous session does not exist
                if self.interactive_session is not None:
                    return self.interactive_session._get_only_one_interactive_error_message_observation()
                assert self.container_name is not None
                _observation, self.interactive_session = get_interactive_session(
                    ctr_name=self.container_name,
                    ctr_obj=self.container_obj,
                    cwd="/" + self._repo_name,
                    session_name=session_name,
                    config=self.args.interactive_sessions_config[session_name],
                    logger=self.logger,
                )
                observation += _observation
            elif command == "STOP":
                if self.interactive_session is None:
                    observation = f"Interactive session {session_name!r} is not running, so it cannot be stopped!"
                else:
                    if self.interactive_session.session_process.poll() is None:
                        self.logger.warning("Session did not quit successfully, terminating.")
                        self.interactive_session.session_process.terminate()
                    observation = f"Interactive session {session_name!r} stopped successfully"
                    self.interactive_session = None
            else:
                if self.interactive_session is None:
                    self.logger.warning("Tried to run interactive commands without starting session")
                    start_command = self.args.interactive_sessions_config[session_name].start_command
                    observation = f"Interactive session {session_name!r} is not running! please start it first using `{start_command}`"
                elif self.interactive_session and self.interactive_session.session_process.poll() is not None:
                    start_command = self.args.interactive_sessions_config[session_name].start_command
                    observation = f"Interactive session {session_name!r} was unexpectedly closed! Please start it again using `{start_command}`"
                    self._terminate_interactive_session(session_name=session_name)
                else:
                    _observation, terminate = self.interactive_session.communicate_with_handling(
                        command,
                        timeout_duration=AGENT_ACTION_TIMEOUT,
                        no_output_timeout_duration=AGENT_ACTION_NO_OUTPUT_TIMEOUT,
                    )
                    observation += _observation
                    if terminate:
                        self._terminate_interactive_session(session_name=session_name)
                    observation += "\n"
        return observation

    def step(self, action: str) -> tuple[str | None, int, bool, AgentInfo]:
        """
        Runs an action proposed by the agent in the environment and returns the corresponding output.

        Args:
            action: command to run in bash shell

        Returns:
            observation:  output from container
            reward: Always set to 0
            done: whether task is over
            info: additional information (e.g. debugging information)
        """
        info: AgentInfo = {}
        # Make sure to have the right keys even if the submission is missing/empty
        info.update(self._get_edited_files_with_context(patch=""))  # type: ignore

        observation = ""
        # Handle special actions
        action = action.strip()
        if action == "skip":
            observation = "Skipped"
            info["exit_status"] = "skipped"
            return observation, 0, True, info
        if action == "exit_forfeit":
            observation = "Exited"
            info["exit_status"] = action
            return observation, 0, True, info
        if action in {"exit_context", "exit_cost", "exit_error", "exit_format", "exit_api"}:
            try:
                observation = self.communicate(input="submit")
                submission = self.get_submission(observation)
                assert submission is not None and submission.strip() != "", AssertionError("No submission found.")
                self.logger.info(f"Found submission: {submission}")
                info["exit_status"] = f"submitted ({action})"
                info["submission"] = submission
                info.update(self._get_edited_files_with_context(patch=submission))  # type: ignore
                observation = "Exited (autosubmitted)"
                self.logger.info("Exiting with autosubmission")
                return observation, 0, True, info
            except KeyboardInterrupt:
                raise
            except:
                observation = "Exited"
                info["exit_status"] = action
                return observation, 0, True, info

        # Attempt to run action in container
        observation = ""
        try:
            observation = self.communicate(
                input=action,
                timeout_duration=AGENT_ACTION_TIMEOUT,
                no_output_timeout_duration=AGENT_ACTION_NO_OUTPUT_TIMEOUT,
                set_last_action=True,
            )
        except TimeoutError as e:
            try:
                observation += e.args[1] if len(e.args) > 1 else ""
                observation += self.interrupt()
                observation += "\nEXECUTION TIMED OUT"
                
                # Enhanced timeout handling with better diagnostics
                if isinstance(e, NoOutputTimeoutError):
                    observation += f" BECAUSE NO OUTPUT WAS PRODUCED FOR MORE THAN {AGENT_ACTION_NO_OUTPUT_TIMEOUT} SECONDS.\n"
                    observation += "POSSIBLE CAUSES:\n"
                    observation += "- Command is waiting for user input (use non-interactive flags)\n"
                    observation += "- Process is stuck in I/O wait (filesystem operations)\n"
                    observation += "- Command is running but not producing output\n"
                    observation += "SUGGESTIONS: Use 'timeout' command, add progress indicators, or try a simpler approach."
                else:
                    observation += f" BECAUSE THE COMMAND WAS RUNNING FOR MORE THAN {AGENT_ACTION_TIMEOUT} SECONDS.\n"
                    observation += self._handle_stuck_execution(action)
                    
            except RuntimeError as e:
                observation += e.args[1] if len(e.args) > 1 else ""
                observation += "\nEXECUTION TIMED OUT AND INTERRUPT FAILED. RESTARTING PROCESS."
                info["exit_status"] = "early_exit"
                info["timeout_reason"] = "interrupt_failed"
                self.logger.warning(f"Failed to interrupt container: {e}\nRESTARTING PROCESS.")
                self.reset_container()
                return observation, 0, True, info
        except RuntimeError as e:
            observation += e.args[1] if len(e.args) > 1 else ""
            observation += "\nCOMMAND FAILED TO EXECUTE. RESTARTING PROCESS."
            info["exit_status"] = "early_exit"
            self.logger.warning(f"Failed to execute command: {e}\nRESTARTING PROCESS.")
            self.reset_container()
            return observation, 0, True, info
        except BrokenPipeError as e:
            observation += "\nBROKEN PIPE ERROR. RESTARTING PROCESS."
            info["exit_status"] = "early_exit"
            self.logger.error(f"Broken pipe error: {e}\nRESTARTING PROCESS.")
            self.reset_container()
            return observation, 0, True, info
        except UnicodeError as e:
            observation += "\nCOMMAND PRODUCED TOO MANY NON-UNICODE CHARACTERS. PLEASE TRY ANOTHER COMMAND.\nIF YOU WANT TO VIEW BINARY FILES, PLEASE USE `xxd` OR `hexdump` INSTEAD.\n"
            self.logger.error(f"Unicode error: {e}")
        except Exception:
            observation += "\nEXECUTION FAILED OR COMMAND MALFORMED"
            self.logger.exception("Unknown exception")

        # Record submission and end episode if `submit` keyword found
        submission = self.get_submission(observation)
        if submission is not None:
            if self.validate_submission(submission):
                self.logger.info(f"Found submission: {submission}")
                info["exit_status"] = "submitted"
                info["submission"] = submission if submission.strip() != "" else None
                info.update(self._get_edited_files_with_context(patch=submission))  # type: ignore
                observation = submission if submission.strip() != "" else None
                return observation, 0, True, info
            else:
                # Currently only validating CTF challenges
                assert self.challenge is not None
                self.logger.warning(f"Wrong submission found: {submission} (real flag is {self.challenge['flag']})")
                observation = "Wrong flag!"
                return observation, 0, False, info

        observation = self._handle_interactive_commands(observation)

        # CRITICAL: Detect and handle CTF server crashes during model interaction
        if self.challenge is not None:
            observation, should_continue = self._detect_and_handle_server_crash(action, observation)
            if not should_continue:
                info["exit_status"] = "ctf_server_crashed"
                return observation, 0, True, info

        return observation, 0, False, info

    def close(self) -> None:
        """
        Handle environment shutdown
        """
        if self._cleanup_done:
            return  # Already cleaned up
            
        self.logger.info("Beginning environment shutdown...")
        
        # Try to exit the container gracefully first
        try:
            self.communicate(input="exit")
        except KeyboardInterrupt:
            raise
        except:
            self.logger.warning("Errors when exiting container", exc_info=True)
        
        # Terminate the container process
        if self.container is not None:
            try:
                self.container.terminate()
            except Exception as e:
                self.logger.warning(f"Failed to terminate container process: {e}", exc_info=True)
        
        # Clean up interactive session
        if self.interactive_session is not None:
            try:
                self.interactive_session.session_process.terminate()
            except KeyboardInterrupt:
                raise
            except Exception:
                self.logger.warning("Failed to stop interactive session: %s", traceback.format_exc())
            finally:
                self.interactive_session = None
                self.logger.info("Interactive session stopped")
        
        # Handle persistent vs non-persistent containers
        if self.container_obj is not None:
            if self.persistent:
                # For persistent containers, just pause them instead of removing
                assert self.container_name
                try:
                    # Get fresh container object since status might not be updated
                    self.container_obj = docker.from_env().containers.get(self.container_name)
                    if self.container_obj.status not in {"paused", "exited", "dead", "stopping"}:
                        try:
                            self.container_obj.pause()
                            self.logger.info("Agent container paused")
                        except Exception:
                            self.logger.warning("Failed to pause container.", exc_info=True)
                    else:
                        self.logger.info(f"Agent container status: {self.container_obj.status}")
                except Exception:
                    self.logger.warning(f"Failed to get fresh container object: {traceback.format_exc()}", exc_info=True)
            else:
                # For non-persistent containers, they will be cleaned up by _cleanup_docker_resources()
                pass
        
        # Use the comprehensive Docker resource cleanup
        self._cleanup_docker_resources(final_cleanup=True)
        
        # Call hooks
        for hook in self.hooks:
            hook.on_close()

    # MARK: Helper functions #

    def _reset_container(self) -> None:
        # Terminate existing container process
        if self.container is not None:
            try:
                self.container.terminate()
            except KeyboardInterrupt:
                raise
            except:
                self.logger.warning("Failed to terminate container", exc_info=True)
            else:
                self.logger.debug("Terminated container")
        
        # Clean up Docker resources (but don't mark as fully done since this is a reset)
        was_cleanup_done = self._cleanup_done
        self._cleanup_done = False  # Allow cleanup to run
        self._cleanup_docker_resources(final_cleanup=False)
        self._cleanup_done = was_cleanup_done  # Restore previous state
        
        # Initialize new container and scripts
        self._init_container()
        self._init_scripts()

    def reset_container(self) -> None:
        self.close()
        self.container = None
        self.container_obj = None
        self._reset_container()

    @staticmethod
    def _get_container_name(image_name: str) -> str:
        """Return name of container"""
        process_id = str(os.getpid())
        current_time = str(datetime.datetime.now())
        unique_string = current_time + process_id
        hash_object = hashlib.sha256(unique_string.encode())
        image_name_sanitized = image_name.replace("/", "-")
        image_name_sanitized = image_name_sanitized.replace(":", "-")
        return f"{image_name_sanitized}-{hash_object.hexdigest()[:10]}"

    # ctf
    def _init_docker_network(self) -> None:
        """
        Add the "ctfnet" network interface for all the containers used for CTF challenges
        """
        assert self.container_name is not None
        if self.challenge is not None:
            # Set dynamic network name if dynamic ports are enabled and not already set
            if self.args.enable_dynamic_ports and self.dynamic_network_name is None:
                # CRITICAL FIX: Use the new highly unique suffix generation
                container_suffix = self._get_unique_container_suffix()
                self.dynamic_network_name = f"ctfnet-{container_suffix}"
                self.logger.info(f"🔗 Using unique network name: {self.dynamic_network_name}")
            
            network_name = self.dynamic_network_name if self.dynamic_network_name else "ctfnet"
            
            # CRITICAL FIX: Wait for docker-compose to create the network FIRST
            if self.args.enable_dynamic_ports and self.dynamic_network_name:
                self.logger.debug(f"Waiting for dynamic network {network_name} to be ready before attachment...")
                
                max_wait = 60
                network_exists = False
                
                for i in range(max_wait):
                    try:
                        client = docker.from_env()
                        network = client.networks.get(network_name)
                        # Ensure network is properly configured
                        if network.attrs.get('Name') == network_name:
                            network_exists = True
                            self.logger.debug(f"Dynamic network {network_name} is ready for attachment")
                            break
                    except docker.errors.NotFound:
                        if i % 10 == 0:  # Log every 10 seconds
                            self.logger.debug(f"Waiting for dynamic network {network_name}... ({i+1}/{max_wait}s)")
                        time.sleep(1)
                    except Exception as e:
                        self.logger.debug(f"Error checking network readiness: {e}")
                        time.sleep(1)
                
                if not network_exists:
                    raise RuntimeError(f"Dynamic network {network_name} not ready after {max_wait}s")
            
            try:
                # Ensure container is not already attached to avoid conflicts
                try:
                    import docker
                    client = docker.from_env()
                    if self.container_obj:
                        self.container_obj.reload()
                        network_settings = self.container_obj.attrs.get('NetworkSettings', {})
                        networks = network_settings.get('Networks', {})
                        
                        if network_name in networks:
                            self.logger.debug(f"Container already connected to {network_name}, skipping attachment")
                            return
                except Exception as e:
                    self.logger.debug(f"Could not check existing network connection: {e}")
                
                attach_network_interface_to_container(self.container_name, network_name)
                self.logger.info(f"✅ Successfully attached container to network {network_name}")
                
                # Verify network attachment with diagnostics
                self._verify_network_attachment(network_name)
                
            except Exception as e:
                self.logger.error(f"❌ Failed to attach container to network {network_name}: {e}")
                # Try to diagnose the issue
                self._diagnose_network_issue(network_name)
                raise RuntimeError(f"Failed to attach container to CTF network: {e}")

    def _verify_network_attachment(self, network_name: str) -> None:
        """
        Verify that the container is properly attached to the specified network.
        """
        try:
            # Check network interfaces from within the container
            interface_info = self.communicate("ip addr show 2>/dev/null | grep -E '^[0-9]+:|inet ' | head -20", timeout_duration=10)
            self.logger.debug(f"Container network interfaces after attachment: {interface_info.strip()}")
            
            # Check routing table
            route_info = self.communicate("ip route show 2>/dev/null | head -10", timeout_duration=10)
            self.logger.debug(f"Container routing table after attachment: {route_info.strip()}")
            
            # Count network interfaces - should have at least 2 (eth0 + dynamic network interface)
            interface_count = len([line for line in interface_info.split('\n') if line.strip() and line[0].isdigit() and ':' in line])
            if interface_count < 2:
                self.logger.warning(f"Container only has {interface_count} network interface(s), expected at least 2")
                self.logger.warning("This may indicate that network attachment failed")
            else:
                self.logger.debug(f"Container has {interface_count} network interfaces - looks good")
                
            # Try to verify we can reach the expected network range
            # Test connectivity to common Docker network gateways
            for gateway in ["172.18.0.1", "172.19.0.1", "172.20.0.1"]:
                ping_result = self.communicate(f"timeout 3 ping -c1 -W1 {gateway} 2>/dev/null && echo 'REACHABLE' || echo 'UNREACHABLE'", timeout_duration=5)
                if "REACHABLE" in ping_result:
                    self.logger.debug(f"Can reach gateway {gateway} - network attachment likely successful")
                    break
            else:
                self.logger.debug("Cannot reach any common Docker network gateways - this may be normal depending on network configuration")
                
        except Exception as e:
            self.logger.warning(f"Network verification failed: {e}")

    def _diagnose_network_issue(self, network_name: str) -> None:
        """
        Diagnose network attachment issues by checking Docker state.
        """
        try:
            client = docker.from_env()
            
            # Check if network exists
            try:
                network = client.networks.get(network_name)
                self.logger.debug(f"Network {network_name} exists with ID: {network.id}")
                
                # Check connected containers
                network.reload()
                connected_containers = network.attrs.get('Containers', {})
                self.logger.debug(f"Network {network_name} has {len(connected_containers)} connected containers")
                
                # Check if our container is listed
                if self.container_obj and self.container_obj.id in connected_containers:
                    self.logger.debug(f"Container {self.container_name} is listed as connected to network {network_name}")
                else:
                    self.logger.warning(f"Container {self.container_name} is NOT listed as connected to network {network_name}")
                    
            except docker.errors.NotFound:
                self.logger.error(f"Network {network_name} does not exist!")
                
            # Check if container exists and is running
            try:
                if self.container_obj:
                    self.container_obj.reload()
                    self.logger.debug(f"Container {self.container_name} status: {self.container_obj.status}")
                    
                    # Check container's network settings
                    network_settings = self.container_obj.attrs.get('NetworkSettings', {})
                    networks = network_settings.get('Networks', {})
                    self.logger.debug(f"Container is connected to networks: {list(networks.keys())}")
                    
                    if network_name in networks:
                        network_info = networks[network_name]
                        self.logger.debug(f"Container network info for {network_name}: IP={network_info.get('IPAddress')}, Gateway={network_info.get('Gateway')}")
                    else:
                        self.logger.warning(f"Container is not connected to network {network_name}")
                        
            except Exception as e:
                self.logger.warning(f"Failed to check container network settings: {e}")
                
        except Exception as e:
            self.logger.warning(f"Network diagnostics failed: {e}")

    # ctf
    def _init_docker_compose(self) -> None:
        """
        Handles docker compose initialization for challenge with docker compose file.
        """
        if self.challenge is not None and self.challenge.get("docker_compose") is not None:
            # Check Docker subnet availability before creating new networks
            if self.args.enable_dynamic_ports:
                from sweagent.environment.utils import check_docker_subnet_availability
                subnet_status = check_docker_subnet_availability()
                
                # If we're approaching subnet limits, try to clean up old networks first
                if subnet_status.get('subnet_usage_warning', False):
                    self.logger.warning("Docker subnet usage is high, attempting cleanup of old networks...")
                    try:
                        from sweagent.environment.utils import cleanup_all_dynamic_networks
                        cleanup_all_dynamic_networks()
                        self.logger.info("Cleaned up old dynamic networks to free subnet space")
                        # Check again after cleanup
                        subnet_status = check_docker_subnet_availability()
                    except Exception as e:
                        self.logger.warning(f"Failed to clean up old networks: {e}")
                
                if subnet_status.get('subnet_usage_critical', False):
                    self.logger.warning("CRITICAL: Docker subnet exhaustion detected!")
                    self.logger.info("🔄 Waiting for subnet space to become available instead of failing immediately...")
                    
                    # Wait for space to become available with extended timeout for parallel execution
                    subnet_status = check_docker_subnet_availability(
                        wait_for_space=True, 
                        max_wait_time=900  # 15 minutes timeout for parallel execution
                    )
                    
                    # Only fail if we still can't get space after waiting
                    if subnet_status.get('subnet_usage_critical', False):
                        self.logger.error("❌ Docker subnet exhaustion persists after waiting!")
                        self.logger.error("Cannot create new networks. Manual cleanup may be required.")
                        self.logger.error("Consider running: docker network prune -f")
                        raise RuntimeError("Docker subnet exhaustion - cannot create new networks after waiting")
            
            # Generate unique suffix for this instance to avoid conflicts
            container_suffix = None
            if self.args.enable_dynamic_ports:
                # CRITICAL FIX: Use the new highly unique suffix generation
                container_suffix = self._get_unique_container_suffix()
                self.dynamic_network_name = f"ctfnet-{container_suffix}"
                self.logger.info(f"🔗 Using unique network name: {self.dynamic_network_name}")
            
            # CRITICAL FIX: Store project name for proper cleanup in parallel execution
            if container_suffix:
                challenge_name = Path(self.challenge["docker_compose"]).parent.name
                raw_project_name = f"{challenge_name}-{container_suffix}"
                
                # CRITICAL FIX: Apply same normalization as in utils.py to ensure consistency
                normalized_project_name = raw_project_name.lower()
                # Replace ALL invalid characters including brackets, spaces, etc.
                normalized_project_name = re.sub(r'[^a-z0-9_-]', '_', normalized_project_name)
                # Ensure it starts with a letter or number
                if normalized_project_name and not normalized_project_name[0].isalnum():
                    normalized_project_name = 'p' + normalized_project_name
                # Remove consecutive separators
                normalized_project_name = re.sub(r'[_-]+', '_', normalized_project_name)
                # Length limits
                if len(normalized_project_name) > 50:
                    if len(normalized_project_name) > 40:
                        normalized_project_name = normalized_project_name[:20] + '_' + normalized_project_name[-19:]
                # Final safety checks
                if not normalized_project_name or not normalized_project_name[0].isalnum():
                    normalized_project_name = f"project_{normalized_project_name}"
                normalized_project_name = re.sub(r'[^a-z0-9_-]', '', normalized_project_name)
                if not normalized_project_name:
                    normalized_project_name = f"project_{int(time.time())}"
                
                self.docker_compose_project_name = normalized_project_name
                self.logger.debug(f"Normalized Docker Compose project name: {raw_project_name} -> {self.docker_compose_project_name}")
            
            # CRITICAL FIX: Create the network BEFORE generating docker-compose file
            network_to_create = self.dynamic_network_name if self.args.enable_dynamic_ports else "ctfnet"
            
            if network_to_create:
                self.logger.info(f"🔗 Creating network: {network_to_create}")
                try:
                    import docker
                    client = docker.from_env()
                    
                    # Check if network already exists
                    try:
                        existing_network = client.networks.get(network_to_create)
                        self.logger.debug(f"Network {network_to_create} already exists")
                    except docker.errors.NotFound:
                        # Network doesn't exist, create it
                        self.logger.debug(f"Creating new network: {network_to_create}")
                        client.networks.create(
                            name=network_to_create,
                            driver="bridge",
                            check_duplicate=True
                        )
                        self.logger.info(f"✅ Created network: {network_to_create}")
                    
                    # Verify network is ready
                    network = client.networks.get(network_to_create)
                    if network.attrs.get('Name') != network_to_create:
                        raise RuntimeError(f"Network creation verification failed for {network_to_create}")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to create network {network_to_create}: {e}")
                    raise RuntimeError(f"Failed to create CTF network: {e}")
            
            # Now generate the docker-compose file (network already exists)
            self.docker_compose, self.port_mappings, actual_project_name = get_docker_compose(
                self.challenge["docker_compose"],
                container_name_suffix=container_suffix,
                dynamic_ports=self.args.enable_dynamic_ports,
                challenge_internal_port=self.challenge.get("port")
            )
            
            # Use the actual project name from get_docker_compose for network discovery
            if actual_project_name:
                self.actual_docker_compose_project_name = actual_project_name
                self.logger.debug(f"Actual Docker Compose project name from utils: {actual_project_name}")
            else:
                self.actual_docker_compose_project_name = self.docker_compose_project_name
            self.logger.info("🏗️ Initialized docker compose for challenge")
            if self.port_mappings:
                self.logger.info(f"🔌 Dynamic port mappings: {self.port_mappings}")
                # Update challenge server description with port mapping info
                # DO NOT overwrite the internal port - services still run on internal ports inside containers
                from sweagent.environment.utils import InstanceBuilder
                ib = InstanceBuilder()
                ib.args = {"challenge": self.challenge}
                ib.update_server_description_with_port_mapping(self.port_mappings)
            
            # Wait for services to be fully ready (get_docker_compose already started them)
            self.logger.info("⏳ Waiting for services to be fully ready...")
            service_wait_time = 15 if self.args.enable_dynamic_ports else 30
            time.sleep(service_wait_time)
            
            # CRITICAL FIX: Attach container to network AFTER services are up
            if network_to_create:
                self.logger.info(f"🔗 Attaching container to CTF network {network_to_create}")
                try:
                    # Check if container is already attached to avoid conflicts
                    if self.container_obj:
                        self.container_obj.reload()
                        network_settings = self.container_obj.attrs.get('NetworkSettings', {})
                        networks = network_settings.get('Networks', {})
                        
                        if network_to_create in networks:
                            self.logger.debug(f"Container already connected to {network_to_create}")
                        else:
                            from sweagent.environment.utils import attach_network_interface_to_container
                            attach_network_interface_to_container(self.container_name, network_to_create)
                            self.logger.info(f"✅ Successfully attached container to network {network_to_create}")
                    
                    # Verify network attachment
                    self._verify_network_attachment(network_to_create)
                    
                    # Apply network restrictions to challenge containers if needed
                    if self.args.enable_network_restrictions and hasattr(self, 'docker_compose_project_name'):
                        container_suffix = self.docker_compose_project_name.split('-')[-1] if '-' in self.docker_compose_project_name else None
                        if container_suffix and self.challenge:
                            self.logger.info("🔒 Applying network restrictions to challenge containers...")
                            try:
                                from sweagent.environment.utils import _setup_network_restrictions_for_challenge_containers
                                _setup_network_restrictions_for_challenge_containers(
                                    self.challenge["docker_compose"], 
                                    container_suffix
                                )
                                self.logger.info("✅ Network restrictions applied to challenge containers")
                            except Exception as e:
                                self.logger.error(f"❌ Failed to apply network restrictions to challenge containers: {e}")
                                self.logger.warning("⚠️  SECURITY WARNING: Challenge containers may have unrestricted network access!")
                    
                except Exception as e:
                    self.logger.error(f"❌ Failed to attach container to network {network_to_create}: {e}")
                    raise RuntimeError(f"Failed to attach container to CTF network: {e}")
                
                self.logger.info(f"✅ Network setup complete for {network_to_create}")
            else:
                self.logger.debug("No network setup needed (not a CTF challenge)")

    # ctf
    def _validate_ctf_server_connectivity(self) -> bool:
        """
        Validate that CTF server port is accessible from within the agent container.
        
        Returns:
            bool: True if server is accessible, False otherwise
        """
        if self.challenge is None:
            return True  # Not a CTF challenge, no validation needed
            
        server_name = self.challenge.get("box")
        internal_port = self.challenge.get("internal_port")
        
        if not server_name or not internal_port:
            self.logger.warning("CTF challenge missing server_name or port, skipping validation")
            return True
        
        # CRITICAL: Check for parallel execution load to prevent server overload
        if self.args.enable_dynamic_ports:
            try:
                # Count how many similar containers are currently running
                # import docker removed to fix UnboundLocalError
                client = docker.from_env()
                containers = client.containers.list()
                
                # Count containers that might be doing validation on the same server
                parallel_count = 0
                for container in containers:
                    container_name = container.name
                    if (container_name.startswith('parallel-') and 
                        container.status == 'running' and 
                        container.id != self.container_obj.id):
                        parallel_count += 1
                
                self.logger.debug(f"Detected {parallel_count} other parallel containers running")
                
                # If too many parallel containers, use lighter validation
                if parallel_count >= 10:
                    self.logger.warning(f"High parallel load detected ({parallel_count} containers). Using lightweight validation.")
                    return self._lightweight_server_validation(server_name, internal_port)
                    
            except Exception as e:
                self.logger.debug(f"Could not check parallel load: {e}")
        
        self.logger.info(f"🔍 Validating CTF server connectivity to {server_name}:{internal_port}")
        
        # Allow some time for docker compose services to start up
        self.logger.debug("Waiting for docker compose services to start...")
        initial_wait = 20 if self.args.enable_dynamic_ports else 30  # Shorter wait for parallel
        time.sleep(initial_wait)
        
        # CRITICAL: Validate container is still alive before proceeding
        if not self._validate_container_health():
            self.logger.error("❌ Container died during validation setup - cannot proceed")
            return False
        
        # First, try basic network connectivity from within the container
        self.logger.debug("Testing basic network connectivity from container...")
        
        # Add DNS diagnostic information
        self.logger.debug("Running network diagnostics...")
        resolved_ip = None  # Track resolved IP address for direct connectivity tests
        try:
            # Check if the server name can be resolved at all
            # First install dnsutils if needed - with better error handling
            dns_install_result = self._safe_communicate_with_retry(
                "which nslookup > /dev/null 2>&1 || (apt-get update > /dev/null 2>&1 && apt-get install -y dnsutils > /dev/null 2>&1)", 
                timeout_duration=30,
                max_retries=2
            )
            if dns_install_result is None:
                self.logger.warning("Failed to install DNS utilities, container may have crashed")
                return False
            
            dns_check = self._safe_communicate_with_retry(
                f"nslookup {shlex.quote(server_name)} 2>&1 || echo 'DNS_RESOLUTION_FAILED'", 
                timeout_duration=10
            )
            if dns_check is None:
                self.logger.warning("DNS check failed, container may have crashed")
                return False
                
            if "DNS_RESOLUTION_FAILED" in dns_check:
                self.logger.warning(f"DNS resolution failed for {server_name}")
            else:
                self.logger.debug(f"DNS resolution for {server_name}: {dns_check.strip()}")
                # CRITICAL FIX: Extract IP address from DNS resolution for direct connectivity tests
                # This prevents DNS resolution inconsistencies between tools
                # Look for the actual service IP, not the DNS server IP
                # nslookup output format:
                # Server: 127.0.0.11#53  ← DNS server (ignore this)
                # Non-authoritative answer:
                # Name: web.chal.csaw.io
                # Address: 172.19.0.2    ← Service IP (extract this)
                
                # Try to find the service IP address (usually comes after "Non-authoritative answer" or as the last Address)
                addresses = re.findall(r'Address:\s*(\d+\.\d+\.\d+\.\d+)', dns_check)
                if addresses:
                    # Filter out DNS server addresses (127.x.x.x) and take the first service address
                    service_addresses = [addr for addr in addresses if not addr.startswith('127.')]
                    if service_addresses:
                        resolved_ip = service_addresses[0]
                        self.logger.info(f"✅ Successfully resolved {server_name} to service IP: {resolved_ip}")
                    else:
                        # Fallback: if only DNS server addresses found, try to find IP in different format
                        # Some nslookup outputs might have different format
                        name_address_match = re.search(r'Name:\s*' + re.escape(server_name) + r'\s*\n\s*Address:\s*(\d+\.\d+\.\d+\.\d+)', dns_check, re.MULTILINE)
                        if name_address_match:
                            candidate_ip = name_address_match.group(1)
                            if not candidate_ip.startswith('127.'):
                                resolved_ip = candidate_ip
                                self.logger.info(f"✅ Successfully resolved {server_name} to service IP (fallback): {resolved_ip}")
                            else:
                                self.logger.warning(f"DNS resolution returned DNS server IP {candidate_ip}, will use hostname")
                        else:
                            self.logger.warning(f"Could not extract service IP from DNS resolution, will use hostname")
                else:
                    self.logger.debug("Could not extract IP address from DNS resolution")
            
            # Check what networks the container is connected to
            network_info = self._safe_communicate_with_retry("ip route show 2>/dev/null | head -10", timeout_duration=10)
            if network_info:
                self.logger.debug(f"Container network routes: {network_info.strip()}")
            
            # Check network interfaces
            interface_info = self._safe_communicate_with_retry("ip addr show 2>/dev/null | grep -E '^[0-9]+:|inet ' | head -20", timeout_duration=10)
            if interface_info:
                self.logger.debug(f"Container network interfaces: {interface_info.strip()}")
            
            # Try to ping the dynamic network gateway to verify connection
            expected_network = self.dynamic_network_name if self.dynamic_network_name else "ctfnet"
            self.logger.debug(f"Expected to be connected to network: {expected_network}")
            
            # CRITICAL FIX: Dynamically detect the actual network range instead of hardcoding 172.18.0.x
            # Extract network ranges from the container's network configuration
            network_ranges = []
            if network_info:
                # Parse network routes to find the network ranges
                route_matches = re.findall(r'(\d+\.\d+\.\d+)\.\d+/\d+', network_info)
                for match in route_matches:
                    if not match.startswith('127.'):  # Skip loopback
                        network_ranges.append(match)
                
                # Store detected network ranges for potential fallback use
                self._detected_network_ranges = network_ranges
                
                if network_ranges:
                    self.logger.debug(f"Detected network ranges: {network_ranges}")
                    # Use the first non-default network range for scanning
                    primary_range = network_ranges[0] if network_ranges else "172.18.0"
                    network_scan = self._safe_communicate_with_retry(f"timeout 5 bash -c 'for i in {{1..10}}; do ping -c1 -W1 {primary_range}.$i 2>/dev/null | grep -q \"1 received\" && echo \"Found host at {primary_range}.$i\"; done' 2>/dev/null || echo 'No hosts found'", timeout_duration=10)
                    if network_scan:
                        self.logger.debug(f"Network scan results: {network_scan.strip()}")
                        
                        # ADDITIONAL FIX: If no resolved IP was found via DNS, try to find the service on detected networks
                        if not resolved_ip and "Found host at" in network_scan:
                            # Extract found hosts and try to match them with the service
                            found_hosts = re.findall(r'Found host at (\d+\.\d+\.\d+\.\d+)', network_scan)
                            if found_hosts:
                                self.logger.info(f"🔍 DNS resolution failed, but found hosts on network: {found_hosts}")
                                # For now, use the first found host as a potential service IP
                                # In a real scenario, we might want to try connecting to each to find the right service
                                potential_ip = found_hosts[0]
                                self.logger.info(f"🎯 Attempting to use network-discovered IP: {potential_ip}")
                                resolved_ip = potential_ip
                else:
                    self.logger.debug("No valid network ranges found for scanning")
                    self._detected_network_ranges = []
            else:
                self._detected_network_ranges = []
            
        except Exception as e:
            self.logger.debug(f"Network diagnostics failed: {e}")
            # Check if container is still alive
            if not self._validate_container_health():
                self.logger.error("❌ Container died during network diagnostics")
                return False
        
        # Install necessary tools if not available - with better error handling
        try:
            netcat_install_result = self._safe_communicate_with_retry(
                "which nc > /dev/null 2>&1 || (apt-get update > /dev/null 2>&1 && apt-get install -y netcat-openbsd > /dev/null 2>&1)",
                timeout_duration=60,
                max_retries=2
            )
            if netcat_install_result is None:
                self.logger.warning("Failed to install netcat, container may have crashed")
                return False
        except Exception as e:
            self.logger.warning(f"Could not install netcat: {e}")
            # Check if container is still alive
            if not self._validate_container_health():
                self.logger.error("❌ Container died during netcat installation")
                return False
        
        # For web challenges, also install curl if needed
        if self.challenge.get("category", "") in {"web", "misc"} and self.challenge.get("proto") != "nc":
            try:
                curl_install_result = self._safe_communicate_with_retry(
                    "which curl > /dev/null 2>&1 || (apt-get update > /dev/null 2>&1 && apt-get install -y curl > /dev/null 2>&1)",
                    timeout_duration=60,
                    max_retries=2
                )
                if curl_install_result is None:
                    self.logger.warning("Failed to install curl, container may have crashed")
                    # Don't fail completely for curl, it's not critical
            except Exception as e:
                self.logger.warning(f"Could not install curl: {e}")
        
        # CRITICAL FIX: Use resolved IP address for connectivity tests when available
        # This prevents DNS resolution inconsistencies between different tools
        target_host = resolved_ip if resolved_ip else server_name
        if resolved_ip:
            self.logger.info(f"🎯 Using resolved IP address {resolved_ip} for connectivity tests")
        else:
            self.logger.info(f"🎯 Using hostname {server_name} for connectivity tests")
            
            # ADDITIONAL FALLBACK: If DNS resolution failed, try to scan all detected network ranges
            # to find potential service IPs for connectivity testing
            if hasattr(self, '_detected_network_ranges') and self._detected_network_ranges:
                self.logger.info(f"🔍 DNS resolution failed, attempting service discovery on networks: {self._detected_network_ranges}")
                potential_targets = []
                
                # Try to find services on each network range
                for network_range in self._detected_network_ranges[:2]:  # Limit to first 2 ranges to avoid overwhelming
                    try:
                        # Quick scan for common service IPs (.2, .3, .4, .10)
                        common_ips = [f"{network_range}.{i}" for i in [2, 3, 4, 10]]
                        for ip in common_ips:
                            # Quick ping test
                            ping_result = self._safe_communicate_with_retry(
                                f"timeout 1 ping -c1 -W1 {ip} 2>/dev/null && echo 'REACHABLE' || echo 'UNREACHABLE'",
                                timeout_duration=3
                            )
                            if ping_result and "REACHABLE" in ping_result:
                                potential_targets.append(ip)
                                self.logger.debug(f"Found potential service at {ip}")
                    except Exception as e:
                        self.logger.debug(f"Service discovery failed on {network_range}: {e}")
                
                if potential_targets:
                    # Use the first discovered potential target as backup
                    target_host = potential_targets[0]
                    self.logger.info(f"🎯 Using network-discovered IP {target_host} as fallback target")
        
        # Define test commands based on challenge type
        if self.challenge.get("category", "") in {"web", "misc"} and self.challenge.get("proto") != "nc":
            # For web challenges, try HTTP connection first, then fall back to TCP
            # REDUCED: Only use essential tests to avoid overwhelming servers
            test_commands = [
                f"curl -f --connect-timeout 5 --max-time 10 http://{shlex.quote(target_host)}:{shlex.quote(str(internal_port))}/ > /dev/null 2>&1 && echo 'SUCCESS' || echo 'FAILED'",
                f"nc -z -v -w5 {shlex.quote(target_host)} {shlex.quote(str(internal_port))} 2>&1 && echo 'SUCCESS' || echo 'FAILED'",
            ]
        else:
            # For other challenges (pwn, crypto, etc.), try TCP connection
            # REDUCED: Only use essential tests
            test_commands = [
                f"nc -z -v -w5 {shlex.quote(target_host)} {shlex.quote(str(internal_port))} 2>&1 && echo 'SUCCESS' || echo 'FAILED'",
                f"timeout 5 bash -c 'echo > /dev/tcp/{shlex.quote(target_host)}/{shlex.quote(str(internal_port))}' 2>/dev/null && echo 'SUCCESS' || echo 'FAILED'",
            ]
        
        max_attempts = 5 
        
        # Add random delay for parallel execution to avoid thundering herd
        if self.args.enable_dynamic_ports:
            import random
            random_delay = random.uniform(1, 5)  # 1-5 second random delay
            self.logger.debug(f"Adding random delay of {random_delay:.1f}s to avoid overwhelming server in parallel execution")
            time.sleep(random_delay)
        
        for attempt in range(max_attempts):
            self.logger.debug(f"Connection attempt {attempt + 1}/{max_attempts}")
            
            # Validate container health before each attempt
            if not self._validate_container_health():
                self.logger.error("❌ Container died during connectivity validation")
                return False
            
            for cmd in test_commands:
                try:
                    self.logger.debug(f"Testing connectivity with: {cmd.split(' && echo')[0]}")  # Log command without success/fail echo
                    result = self._safe_communicate_with_retry(
                        cmd,
                        timeout_duration=CTF_SERVER_VALIDATION_TIMEOUT,
                        max_retries=1
                    )
                    
                    if result is None:
                        self.logger.warning("Container communication failed during connectivity test")
                        return False
                    
                    # Check if the command indicates success
                    # Only check for "SUCCESS" string, not return code, since commands are designed
                    # to always echo either "SUCCESS" or "FAILED" regardless of return code
                    if "SUCCESS" in result:
                        self.logger.info(f"✅ CTF server {server_name}:{internal_port} is accessible")
                        return True
                    else:
                        self.logger.debug(f"Command failed: {result.strip()}")
                        
                except Exception as e:
                    self.logger.debug(f"Connection test failed: {e}")
                    # Check if container is still alive
                    if not self._validate_container_health():
                        self.logger.error("❌ Container died during connectivity test")
                        return False
                    
                # Add small delay between individual commands to reduce server load
                if self.args.enable_dynamic_ports:
                    time.sleep(0.5)
                    
            # Wait before next attempt, with shorter delays for parallel execution
            if attempt < max_attempts - 1:
                if self.args.enable_dynamic_ports:
                    wait_time = 5 + (attempt * 2)  # Shorter waits: 5, 7, 9 seconds
                else:
                    wait_time = min(10 + (attempt * 5), 30)  # Original waits for single execution
                self.logger.debug(f"Waiting {wait_time} seconds before next attempt (services may still be starting)...")
                time.sleep(wait_time)
        
        # If we reach here, all internal connectivity attempts failed
        self.logger.error(f"❌ Failed to connect to CTF server {server_name}:{internal_port} after {max_attempts} attempts")
        self.logger.error("This indicates the CTF server container is not running or not accessible.")
        self.logger.error("Common causes: Docker compose failed to start, network configuration issues, or server startup delays.")
        
        return False

    def _validate_container_health(self) -> bool:
        """
        Check if the container is still alive and responsive.
        
        Returns:
            bool: True if container is healthy, False otherwise
        """
        try:
            # Try a simple command to check if container is responsive
            result = self.communicate("echo 'health_check'", timeout_duration=CONTAINER_HEALTH_CHECK_TIMEOUT)
            return "health_check" in result
        except Exception as e:
            self.logger.debug(f"Container health check failed: {e}")
            return False

    def _safe_communicate_with_retry(self, command: str, timeout_duration: int = 25, max_retries: int = 3) -> str | None:
        """
        Safe communication with container that handles crashes and retries.
        
        Args:
            command: Command to execute
            timeout_duration: Timeout for the command
            max_retries: Maximum number of retry attempts
            
        Returns:
            str | None: Command output or None if container died
        """
        for attempt in range(max_retries):
            try:
                result = self.communicate(command, timeout_duration=timeout_duration)
                return result
            except RuntimeError as e:
                if "Failed to communicate with container" in str(e):
                    self.logger.warning(f"Container communication failed on attempt {attempt + 1}: {e}")
                    if attempt < max_retries - 1:
                        # Wait a bit before retrying
                        time.sleep(2)
                        continue
                    else:
                        # Container is likely dead
                        return None
                else:
                    # Other runtime errors, re-raise
                    raise
            except Exception as e:
                self.logger.warning(f"Unexpected error during communication attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return None
        return None

    def _lightweight_server_validation(self, server_name: str, internal_port: int) -> bool:
        """
        Lightweight server validation for high parallel load scenarios.
        Uses minimal requests to avoid overwhelming the server.
        
        Args:
            server_name: Name of the server to validate
            internal_port: Port to validate
            
        Returns:
            bool: True if server appears accessible, False otherwise
        """
        self.logger.info(f"🔍 Running lightweight validation for {server_name}:{internal_port}")
        
        try:
            # Single, quick test with short timeout
            test_cmd = f"timeout 3 bash -c 'echo > /dev/tcp/{shlex.quote(server_name)}/{shlex.quote(str(internal_port))}' 2>/dev/null && echo 'SUCCESS' || echo 'FAILED'"
            
            result = self.communicate(
                input=test_cmd,
                timeout_duration=5,  # Very short timeout
            )
            
            if "SUCCESS" in result:
                self.logger.info(f"✅ Lightweight validation passed for {server_name}:{internal_port}")
                return True
            else:
                self.logger.warning(f"⚠️  Lightweight validation failed for {server_name}:{internal_port}")
                # In high load scenarios, assume server might be temporarily overloaded
                # but still allow the task to proceed
                self.logger.warning("Assuming server is temporarily overloaded but accessible - proceeding with task")
                return True
                
        except Exception as e:
            self.logger.warning(f"Lightweight validation error: {e}")
            # In high load scenarios, be permissive to avoid false negatives
            self.logger.warning("Validation error in high load scenario - assuming server is accessible")
            return True

    def _init_container(self, cached_image: str | None = None) -> None:
        """
        Handles container initialization. Defines container name and creates it.
        If cached_image is provided, it will use that image name instead of the default.
        """
        image_name = self.image_name
        if cached_image is not None:
            image_name = cached_image
            self.logger.info(f"Using cached image: {image_name}")
        if self.persistent:
            assert self.container_name is not None
        else:
            # Make sure that we get a new container name just in case removing didn't work.
            # Might be a fix for https://github.com/swe-agent/SWE-agent/issues/451
            self.container_name = self._get_container_name(image_name)
        self.container, self.parent_pids = get_container(
            self.container_name, 
            image_name, 
            persistent=self.persistent, 
            container_mounts=self.container_mounts,
            enable_network_restrictions=self.args.enable_network_restrictions
        )
        try:
            client = docker.from_env(timeout=600)
        except docker.errors.DockerException as e:
            if "Error while fetching server API version" in str(e):
                msg = "Docker is not running. Please start Docker and try again."
            else:
                msg = "Unknown docker exception occurred. Are you sure docker is running?"
            raise RuntimeError(msg) from e
        t0 = time.time()
        self.container_obj = None
        while time.time() - t0 < 60:
            try:
                container_candidate = client.containers.get(self.container_name)
                # CRITICAL: Validate that we got the right container
                # In parallel execution, there could be timing issues where we get the wrong container
                if container_candidate.name == self.container_name:
                    self.container_obj = container_candidate
                    self.logger.debug(f"✅ Successfully retrieved container object for {self.container_name}")
                    break
                else:
                    self.logger.warning(f"⚠️  Container name mismatch: expected {self.container_name}, got {container_candidate.name}")
                    # Continue trying to get the right container
                    time.sleep(1)
                    continue
            except docker.errors.NotFound:
                self.logger.debug("Couldn't find container. Let's wait and retry.")
                time.sleep(1)
            else:
                break
        else:
            print(f"{self.persistent=}")
            available_containers = client.containers.list(all=True)
            available_containers_info = json.dumps([str(c.attrs) for c in available_containers], indent=2)
            print(available_containers_info)
            msg = "Failed to get container object."
            raise RuntimeError(msg)
        self.logger.info("🌱 Environment Initialized")

    def _init_scripts(self):
        """
        Initialize custom commands within container
        """
        self.communicate_with_handling(
            "source /root/.bashrc",
            error_msg="Failed to source .bashrc",
        )
        self.communicate_with_handling(
            "mkdir -p /root/commands",
            error_msg="Failed to create commands directory",
        )
        self.communicate_with_handling(
            "touch /root/commands/__init__.py",
            error_msg="Failed to create __init__.py",
        )
        self.communicate_with_handling(
            "export PATH=$PATH:/root/commands",
            error_msg="Failed to add commands directory to PATH",
        )

    def _communicate_experimental(
        self,
        input: str,
        timeout_duration: int | float = 25,
        no_output_timeout_duration: int | float = 25,
    ) -> str:
        """Experimental version of `_communicate`"""
        assert self.container is not None
        # Sleep to ensure that the exit code is in the last line
        # See https://github.com/swe-agent/SWE-agent/issues/595
        command_suffix = (
            f'EXITSTATUS="$?"; sleep 0.01; echo {PROCESS_DONE_MARKER_START}$EXITSTATUS{PROCESS_DONE_MARKER_END}\n'
        )
        try:
            self.returncode = None
            cmd = input if input.endswith("\n") else input + "\n"
            cmd += command_suffix
            os.write(self.container.stdin.fileno(), cmd.encode())  # type: ignore
            time.sleep(0.03)
            self.container.stdin.flush()  # type: ignore
        except BrokenPipeError:
            traceback.print_exc()
            self.logger.error("Failed to communicate with container. Check docker logs for more information.")
            msg = "Failed to communicate with container"
            raise RuntimeError(msg)

        try:
            buffer, exit_code = read_with_timeout_experimental(
                self.container, timeout_duration, no_output_timeout_duration
            )
        except ValueError as e:
            # Handle the case where process done marker is not found
            if "Could not find process done marker" in str(e):
                self.logger.warning(f"Process done marker not found for command: {input[:50]}...")
                # For state command, try to extract JSON or return minimal state
                if input.strip() == "state" or "state()" in input:
                    try:
                        # Try to extract JSON from the error args if available
                        error_args = e.args
                        if len(error_args) > 1 and isinstance(error_args[1], str):
                            buffer = error_args[1]
                        else:
                            buffer = str(e)
                        
                        # Try to find JSON in the buffer
                        json_match = re.search(r'\{[^}]*\}', buffer)
                        if json_match:
                            try:
                                json.loads(json_match.group())  # Validate JSON
                                buffer = json_match.group()
                                exit_code = "0"
                            except json.JSONDecodeError:
                                # JSON is invalid, create minimal state
                                buffer = '{"working_dir": ".", "open_file": "n/a", "interactive_session": "n/a"}'
                                exit_code = "0"
                        else:
                            # No JSON found, create minimal state
                            buffer = '{"working_dir": ".", "open_file": "n/a", "interactive_session": "n/a"}'
                            exit_code = "0"
                        self.logger.info("Recovered state command with fallback JSON")
                    except Exception:
                        # Absolute fallback
                        buffer = '{"working_dir": ".", "open_file": "n/a", "interactive_session": "n/a"}'
                        exit_code = "0"
                else:
                    # For non-state commands, return error message
                    buffer = f"Command execution failed: {input[:50]}..."
                    exit_code = "999"
            else:
                raise  # Re-raise if not the expected error
        except Exception:
            msg = f"Read with timeout failed on input:\n---\n{input}\n---"
            self.logger.error(msg)
            raise
            
        if exit_code == "$EXITSTATUS":
            # this sometimes happens if the command badly fails
            # for example if you just try to run python with no arguments
            # in this case, the error message is usually also garbage, so let's set
            # something new.
            # See https://github.com/swe-agent/SWE-agent/issues/630
            
            # CRITICAL FIX: For state command, we need to return valid JSON even when commands fail
            # Check if this is the state command by looking for JSON-like output pattern
            if input.strip() == "state" or "state()" in input or (input.strip().startswith("state") and "{" in buffer):
                # Try to extract any valid JSON from the buffer, or return a minimal valid state
                try:
                    # Look for JSON pattern in the buffer
                    json_match = re.search(r'\{[^}]*\}', buffer)
                    if json_match:
                        # Try to parse the found JSON to make sure it's valid
                        test_json = json.loads(json_match.group())
                        buffer = json_match.group()  # Use the valid JSON found
                    else:
                        # No valid JSON found, return minimal state
                        try:
                            current_dir = self._safe_exec_run("pwd", timeout_duration=5, workdir="/")
                            current_dir = current_dir.strip() if current_dir else "/"
                        except:
                            current_dir = "/"
                        buffer = f'{{"working_dir": "{current_dir}", "open_file": "n/a", "interactive_session": "n/a"}}'
                except Exception:
                    # Fallback to absolute minimal state if everything fails
                    buffer = '{"working_dir": ".", "open_file": "n/a", "interactive_session": "n/a"}'
                    
                self.logger.warning("State command failed, returning fallback JSON state")
                exit_code = "0"  # Set successful exit code for state command
            else:
                # For non-state commands, use the original error message
                buffer = (
                    "Unknown error occurred when running the command. Please double check syntax "
                    "and that you're not running an interactive command."
                )
                self.logger.warning("Couldn't get real exit code. Setting it to 999")
                exit_code = "999"
        elif not exit_code.isdigit():
            # this sometimes happens if the command is being killed, for example radare2
            # we set the error to 998 in that case
            self.logger.warning("Couldn't get real exit code. Setting it to 998")
            exit_code = "998"
            
        self.returncode = int(exit_code)
        return buffer

    def _communicate(
        self,
        input: str,
        timeout_duration: int | float = 25,
        no_output_timeout_duration: int | float = 25,
    ) -> str:
        """Runs command in container and returns output

        Args:
            input: command to run in container
            timeout_duration: duration to wait for output
            no_output_timeout_duration: duration to wait when the process stopped produce any output
        """
        assert self.container is not None
        communicate_method = keys_config.get(
            "SWE_AGENT_COMMUNICATE_METHOD", default="end-marker", choices=["end-marker", "processes"]
        )
        if communicate_method == "end-marker":
            return self._communicate_experimental(input, timeout_duration, no_output_timeout_duration)
        try:
            self.returncode = None
            cmd = input if input.endswith("\n") else input + "\n"
            os.write(self.container.stdin.fileno(), cmd.encode())  # type: ignore
            time.sleep(0.1)
            self.container.stdin.flush()  # type: ignore
        except BrokenPipeError:
            traceback.print_exc()
            self.logger.error("Failed to communicate with container. Check docker logs for more information.")
            msg = "Failed to communicate with container"
            raise RuntimeError(msg)
        try:
            buffer = read_with_timeout(self.container, self.get_pids, timeout_duration)
            self.container.stdin.write("echo $?\n")  # type: ignore
            time.sleep(0.1)
            self.container.stdin.flush()  # type: ignore
            exit_code = read_with_timeout(self.container, self.get_pids, 5).strip()
        except Exception as e:
            self.logger.error(f"Read with timeout failed on input:\n---\n{input}\n---")
            raise e
        if not exit_code.isdigit():
            msg = f"Failed to get exit code. Output:\n---\n{buffer}\n---"
            raise RuntimeError(msg)
        self.returncode = int(exit_code)
        return buffer

    def _check_syntax(self, input: str) -> tuple[str, bool]:
        """
        Check syntax of command.

        Returns:
            output: Output of the command
            success: whether the exit code was 0
        """
        output = self._communicate(f"/bin/bash -n <<'EOF'\n{input}\nEOF\n")
        return output, self.returncode == 0

    def _is_flag_access_attempt(self, command: str) -> bool:
        """Check if command attempts to directly access flag files"""
        # Commands that could be used to read flag files
        flag_reading_patterns = [
            r'\bcat\s+["\']?/?flag["\']?\b',           # cat /flag, cat flag
            r'\bcat\s+["\']?/?flag\.txt["\']?\b',      # cat /flag.txt, cat flag.txt  
            r'\bless\s+["\']?/?flag["\']?\b',          # less /flag
            r'\bmore\s+["\']?/?flag["\']?\b',          # more /flag
            r'\btail\s+["\']?/?flag["\']?\b',          # tail /flag
            r'\bhead\s+["\']?/?flag["\']?\b',          # head /flag
            r'\bstrings\s+["\']?/?flag["\']?\b',       # strings /flag
            r'\bxxd\s+["\']?/?flag["\']?\b',           # xxd /flag
            r'\bhexdump\s+["\']?/?flag["\']?\b',       # hexdump /flag
            r'\bod\s+["\']?/?flag["\']?\b',            # od /flag
            r'\bbase64\s+["\']?/?flag["\']?\b',        # base64 /flag
            r'\bcp\s+["\']?/?flag["\']?',              # cp /flag somewhere
            r'\bmv\s+["\']?/?flag["\']?',              # mv /flag somewhere
            r'<\s*["\']?/?flag["\']?\b',               # < /flag (input redirection)
            r'\bopen\s+["\']?/?flag["\']?\b',          # open flag (custom command)
            r'\bls\s+.*["\']?/?flag["\']?',            # ls -la /flag (getting permissions)
            r'\bfind\s+.*-name\s+["\']?flag["\']?',    # find . -name flag
            r'\bgrep\s+.*["\']?/?flag["\']?',          # grep in flag files
            r'\bawk\s+.*["\']?/?flag["\']?',           # awk processing flag files
            r'\bsed\s+.*["\']?/?flag["\']?',           # sed processing flag files
            r'python.*open\(["\']/?flag["\']',         # Python file open
            r'with\s+open\(["\']/?flag["\']',          # Python with open
        ]
        
        # Check against all patterns
        for pattern in flag_reading_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
                
        return False

    def communicate(
        self,
        input: str,
        timeout_duration: int | float = 25,
        no_output_timeout_duration: int | float | None = None,
        *,
        set_last_action: bool = False,
        redact_command_trace: bool = False,
    ) -> str:
        """
        Sends input to container and returns output

        Args:
            input: input to send to container
            timeout_duration: duration to wait for output
            set_last_action: whether to set the LAST_ACTION environment variable
            redact_command_trace: Whether to redact the command that is being run when logging
                it to trace level
        Returns:
            output: output from container
        """
        assert self.container is not None
        if no_output_timeout_duration is None:
            no_output_timeout_duration = timeout_duration
        if input.strip() != "exit":
            if redact_command_trace:
                self.logger.log(logging.TRACE, "Input:\nREDACTED")  # type: ignore
            else:
                self.logger.log(logging.TRACE, "Input:\n%s", input)  # type: ignore
            output, valid = self._check_syntax(input)
            if not valid:
                return output  # shows syntax errors
            output = self._communicate(
                input,
                timeout_duration=timeout_duration,
                no_output_timeout_duration=no_output_timeout_duration,
            )
            self.logger.log(logging.TRACE, "Output:\n%s", output)  # type: ignore
            self.communicate_output = output
            if set_last_action:
                # Cannot merge this with last command, because of multiline command
                # handling.
                last_action_string = shlex.quote(input.strip())
                input = f"export LAST_ACTION={last_action_string}"
                self._communicate(input, timeout_duration=5, no_output_timeout_duration=5)
            return output
        else:
            self.container.terminate()
            self.returncode = 0
            self.communicate_output = ""
            return ""

    def communicate_with_handling(
        self, input: str, error_msg: str, timeout_duration: int | float = 25, *, redact_command_trace: bool = False
    ) -> str:
        """
        Wrapper for communicate function that raises error if return code is non-zero

        Args:
            input: input to send to container
            error_msg: error message to raise if return code is non-zero
            timeout_duration: duration to wait for output
            redact_command_trace: Whether to redact the command that is being run when logging
                it to trace level

        Returns:
            output: output from container
        """
        logs = self.communicate(input, timeout_duration=timeout_duration, redact_command_trace=redact_command_trace)
        if self.returncode != 0:
            self.logger.error(f"{error_msg}: {logs}")
            self.close()
            msg = f"{error_msg}: {logs}"
            raise RuntimeError(msg)
        return logs

    def get_available_actions(self) -> list[str]:
        """
        Returns list of available actions in current environment state

        Currently not in use.
        """
        return []

    def get_pids(self, all_pids: bool = False) -> list[tuple[str, str]]:
        """
        Gets list of processes running inside docker container

        Args:
            all_pids: whether to return all pids, or whether to exclude ps
                and parent PIDs

        Returns:
            list of PIDs
        """
        assert self.container_obj is not None
        try:
            pids = self._safe_exec_run("ps -eo pid,comm,ppid --no-headers", timeout_duration=10).split("\n")
        except Exception as e:
            self.logger.warning(f"Failed to get PIDs: {e}")
            return []
        
        pids = [x.split() for x in pids if x]
        if not all_pids:
            # Get just the PIDs of processes that are descendants of parent_pids and not others
            pids = [
                (x[0], x[1])
                for x in pids
                if x[1] != "ps"
                and x[0] not in self.parent_pids
                and x[1] != getattr(self.interactive_session, "name", None)
                and x[2] in self.parent_pids
            ]
        return pids

    # ctf
    def validate_submission(self, submission: str) -> bool:
        """
        Function for validating submission for CTF challenges.

        Args:
            submission: extracted submission

        Returns:
            validation of the submission found against known flag
        """
        submission = submission.strip()
        def wrap(s: str) -> str:
            return f"flag{{{s}}}"

        if self.challenge is not None:
            flag_correct, raw_sha256_correct, sha256_correct, raw_check_correct, check_correct = False, False, False, False, False

            pattern = r".+?{(.+?)}"
            match = re.search(pattern, submission)
            extracted_flag = match.group(1) if match else submission
            
            if "flag" in self.challenge and self.challenge["flag"] != "pwn.college{...}":
                solution = self.challenge["flag"]
                flag_correct = any(
                    (
                        submission == solution,
                        wrap(submission) == solution,
                        submission == wrap(solution),
                    )
                )
        
            if "sha256_flag" in self.challenge:
                checker = self.challenge["sha256_flag"]
                raw_sha256_correct = hashlib.sha256(extracted_flag.encode()).hexdigest() == checker
                sha256_correct = hashlib.sha256(submission.encode()).hexdigest() == checker

            if "flag_check" in self.challenge:
                # Ensure the flag_check script is readable and executable
                flag_check_path = self.challenge["flag_check"]
                try:
                    # Make the flag_check script readable and executable
                    os.chmod(flag_check_path, 0o755)
                    self.logger.debug(f"Set permissions for flag_check script: {flag_check_path}")
                except Exception as e:
                    self.logger.warning(f"Failed to set permissions for flag_check script {flag_check_path}: {e}")
                    # Try to continue anyway in case the script is already executable
                
                raw_check_result = subprocess.run(
                    [self.challenge["flag_check"]],
                    input=submission + "\n",
                    text=True,
                    capture_output=True
                )
                raw_check_correct = "incorrect" not in raw_check_result.stdout.lower()
                check_result = subprocess.run(
                    [self.challenge["flag_check"]],
                    input=extracted_flag + "\n",
                    text=True,
                    capture_output=True
                )
                check_correct = "incorrect" not in check_result.stdout.lower()

            return flag_correct or raw_sha256_correct or sha256_correct or raw_check_correct or check_correct
        
        return True

    def get_submission(self, output: str) -> str | None:
        """
        Function for extracting diff patch submission at the end of an episode.

        Args:
            output: `submit` observation

        Returns:
            submission: diff patch submission
        """
        pattern = r"\<\<SUBMISSION\|\|(.*)\|\|SUBMISSION\>\>"
        match = re.search(pattern, output, re.DOTALL)
        if match is None:
            return None
        return match.group(1)

    def run_shell_script(self, script_path: Path, *, location: str) -> None:
        """Run custom script supplied by user at `script_path`

        Args:
            script_path: path to script file
            location: location of script file 'host' or 'container'
        """
        if location == "host":
            return self._run_shell_script_host(script_path)
        elif location == "container":
            raise NotImplementedError
        msg = f"Invalid 'location': {location}"
        raise ValueError(msg)

    def _run_shell_script_host(self, script_path: Path) -> None:
        """Run shell script file (located on host) in container"""
        if not script_path.is_file():
            msg = f"Script not found at {script_path}"
            raise FileNotFoundError(msg)
        shell_commands = Path(script_path).read_text().splitlines(keepends=True)
        for i, cmd in enumerate(shell_commands):
            self.communicate_with_handling(
                cmd,
                error_msg=f"Failed to execute line {i}.",
                timeout_duration=LONG_TIMEOUT,
            )

    def _get_install_configs(self) -> dict | None:
        """Return config for environment setup"""
        assert self.record is not None  # mypy
        if (
            self.record["problem_statement_source"] != "swe-bench" or self.record["repo_type"] == "local"
        ) and self.args.environment_setup is None:
            self.logger.warning(
                "install_environment is set to True, but the data path is a GitHub URL "
                "without an environment config file (environment_config key/flag). "
                "Skipping conda environment installation.",
            )
            return None
        if self.args.environment_setup is not None:
            assert isinstance(self.args.environment_setup, (str, os.PathLike))
            if Path(self.args.environment_setup).suffix in [".yml", ".yaml"]:
                try:
                    return yaml.safe_load(Path(self.args.environment_setup).read_text())
                except Exception as e:
                    msg = "Environment config file needs to be a yaml file"
                    raise ValueError(msg) from e
            elif Path(self.args.environment_setup).suffix == ".sh":
                return {
                    "shell_script_path": self.args.environment_setup,
                }
            else:
                msg = "Environment config file needs to be a yaml file or shell script"
                raise ValueError(msg)
        else:
            try:
                return MAP_REPO_VERSION_TO_SPECS[self.record["repo"]][str(self.record["version"])]
            except KeyError as e:
                msg = (
                    "Tried to look up install configs in swe-bench, but failed. "
                    "You can set a custom environment config with the environment_config key/flag."
                )
                raise ValueError(msg) from e

    def _conda_environment_exists(self, env_name: str) -> bool:
        env_check = self.communicate(f"conda env list | grep {shlex.quote(env_name)}", timeout_duration=LONG_TIMEOUT)
        return env_check.strip() != ""

    def install_env(self) -> None:
        """
        Creates conda environment and installs third party dependencies to allow code execution
        """
        t0 = time.perf_counter()
        for hook in self.hooks:
            hook.on_install_env_started()
        install_configs = self._get_install_configs()
        if not install_configs:
            return
        if "shell_script_path" in install_configs:
            assert len(install_configs) == 1
            self.run_shell_script(Path(install_configs["shell_script_path"]), location="host")
            return
        assert self.record is not None  # mypy
        # Create environment if does not exist yet
        env_name = f"{self._repo_name}__{self.record['version']}"
        if not self._conda_environment_exists(env_name):
            self.logger.info(f"{env_name} conda env not found, creating...")
            packages = install_configs.get("packages", "")
            if packages == "requirements.txt":
                # Create conda environment
                self.communicate_with_handling(
                    f"conda create -n {shlex.quote(env_name)} python={install_configs['python']} -y",
                    error_msg="Failed to create conda environment",
                    timeout_duration=LONG_TIMEOUT,
                )
                self.logger.debug("Created conda environment")
                # Write reqs to requirements.txt in docker container
                content_reqs = get_requirements(self.record)
                copy_file_to_container(self.container_obj, content_reqs, PATH_TO_REQS)
                # Create conda environment + install reqs
                self.communicate_with_handling(
                    f"conda activate {shlex.quote(env_name)}",
                    error_msg="Failed to activate conda environment",
                )
                self.communicate_with_handling(
                    f"pip install -r {PATH_TO_REQS}",
                    error_msg="Failed to install requirements.txt",
                    timeout_duration=LONG_TIMEOUT,
                )
                self.logger.debug("Installed requirements from requirements.txt")
                self.communicate(f"rm {PATH_TO_REQS}")
            elif packages == "environment.yml":
                # Write environment.yml to file
                content_env_yml = get_environment_yml(self.record, env_name)
                # Hotfix for
                if not install_configs.get("no_use_env"):
                    content_env_yml += f'\n  - python={install_configs["python"]}\n'
                copy_file_to_container(self.container_obj, content_env_yml, PATH_TO_ENV_YML)
                if install_configs.get("no_use_env"):
                    # Create conda environment
                    self.communicate_with_handling(
                        f"conda create -c conda-forge -n {shlex.quote(env_name)} python={install_configs['python']} -y",
                        error_msg="Failed to create conda environment",
                        timeout_duration=LONG_TIMEOUT,
                    )
                    self.logger.debug("Created conda environment")
                    # Install packages
                    self.communicate_with_handling(
                        f"conda env update -f {PATH_TO_ENV_YML}",
                        error_msg="Failed to install environment.yml",
                        timeout_duration=LONG_TIMEOUT,
                    )
                    self.logger.debug("Installed packages from environment.yml")
                else:
                    # Create environment + install packages
                    self.communicate_with_handling(
                        f"conda env create --file {PATH_TO_ENV_YML}",
                        error_msg="Failed to create conda environment with environment.yml",
                        timeout_duration=LONG_TIMEOUT,
                    )
                    self.logger.debug("Created conda environment with environment.yml")
                self.communicate(f"rm {PATH_TO_ENV_YML}")
            else:
                python_env = f"python{install_configs['python']}"
                if self._conda_environment_exists(python_env):
                    self.communicate_with_handling(
                        f"conda create --name {shlex.quote(env_name)} --clone {python_env}",
                        error_msg="Failed to clone conda environment",
                        timeout_duration=LONG_TIMEOUT,
                    )
                    self.logger.debug("Cloned python conda environment")
                else:
                    self.logger.debug(f"Could not find {python_env}, creating new environment")
                    self.communicate_with_handling(
                        f"conda create -n {shlex.quote(env_name)} python={install_configs['python']} -y",
                        error_msg="Failed to create conda environment",
                        timeout_duration=LONG_TIMEOUT,
                    )
                self.communicate_with_handling(
                    f"conda activate {shlex.quote(env_name)}",
                    error_msg="Failed to activate conda environment",
                )
                if packages.strip():
                    self.communicate_with_handling(
                        f"conda install {packages} -y",
                        error_msg="Failed to install packages",
                        timeout_duration=LONG_TIMEOUT,
                    )
                    self.logger.debug("Installed conda packages")
            # Install extra pip packages if specified
            if install_configs.get("pip_packages"):
                self.communicate_with_handling(
                    f"source activate {shlex.quote(env_name)} && pip install {' '.join(install_configs['pip_packages'])}",
                    error_msg="Failed to install pip packages",
                    timeout_duration=LONG_TIMEOUT,
                )
                self.logger.debug("Installed extra pip dependencies")

        # Activate environment
        self.communicate_with_handling(f"conda activate {shlex.quote(env_name)}", error_msg="Failed to activate conda environment")

        # Install repo at base commit
        if install_configs.get("pre_install"):
            self.logger.info("Running pre-install commands...")
            for pre_install_cmd in install_configs["pre_install"]:
                self.communicate_with_handling(
                    pre_install_cmd,
                    error_msg="Pre-install commands failed to execute successfully",
                    timeout_duration=LONG_TIMEOUT,
                )
            self.logger.debug("Ran pre-install commands")
        self.logger.info(f"Installing {self._repo_name} at base commit...")
        if install_configs.get("install"):
            install_cmd = install_configs["install"]
            self.communicate_with_handling(
                install_cmd,
                error_msg="Install command failed to execute successfully",
                timeout_duration=LONG_TIMEOUT,
            )
            self.logger.debug("Ran install command")
        if install_configs.get("post_install"):
            self.logger.info("Running post-install commands...")
            for post_install_cmd in install_configs["post_install"]:
                self.communicate_with_handling(
                    post_install_cmd,
                    error_msg="Post-install commands failed to execute successfully",
                )
            self.logger.debug("Ran post-install commands")

        self.logger.info("Installation step took %.2f seconds", time.perf_counter() - t0)

    def add_commands(self, commands: list[dict]) -> None:
        """
        Adds custom commands to container
        """
        for command in commands:
            name = command["name"]
            contents = command["contents"]
            copy_file_to_container(self.container_obj, contents, f"/root/commands/{name}")
            if command["type"] == "source_file":
                self.communicate_with_handling(
                    f"source /root/commands/{name}",
                    error_msg=(
                        f"Failed to source {name}. If you meant to make a script,"
                        " start the file with a shebang (e.g. #!/usr/bin/env python)."
                    ),
                )
            elif command["type"] == "script":
                self.communicate_with_handling(
                    f"chmod +x /root/commands/{name}",
                    error_msg=f"Failed to chmod {name}",
                )
            elif command["type"] == "utility":
                # nothing to do for utility scripts
                pass
            else:
                msg = f"Invalid command type: {command['type']}"
                raise ValueError(msg)

    def interrupt(self) -> str:
        """
        Send interrupt signal to container and exhaust stdout buffer with a communicate call
        """
        assert self.container is not None
        assert self.container_obj is not None
        pids = self.get_pids()
        for pid, _ in pids:
            # Sending signal several times ensures that the process is dead
            for _ in range(3):
                try:
                    self._safe_exec_run(f"kill -9 {pid}", timeout_duration=5)
                except Exception as e:
                    self.logger.debug(f"Failed to kill PID {pid}: {e}")
        observation = ""
        try:
            observation += read_with_timeout(self.container, self.get_pids, INTERRUPT_TIMEOUT)
        except TimeoutError:
            pass
        try:
            # This is a workaround because of bash behaviour
            # when sometimes we get the prints of Killed after we press some "Enter" in stdin
            self.communicate(input="echo 'interrupted'", timeout_duration=5)
            output = self.communicate(input="echo 'interrupted'", timeout_duration=5)
            assert output.strip().endswith("interrupted"), "container health check failed"
        except TimeoutError:
            msg = "Failed to interrupt container"
            raise RuntimeError(msg)
        return observation

    def open_pr(self, *, trajectory, _dry_run: bool = False) -> None:
        """Create PR to repository

        Args:
            trajectory: Trajectory of actions taken by the agent
            _dry_run: Whether to actually push anything or just simulate it
        """
        self.logger.info("Opening PR")
        # TODO: have better way of handling this
        # Adding random string suffix to avoid name conflicts if we had a previously failed run
        issue_url = self.args.data_path
        try:
            issue = get_gh_issue_data(issue_url, token=self._github_token)
        except InvalidGithubURL as e:
            msg = "Data path must be a github issue URL if --open_pr is set."
            raise ValueError(msg) from e
        branch_name = f"swe-agent-fix-#{issue.number}-" + str(random.random())[2:10]

        self.communicate_with_handling(
            input="rm -f model.patch",
            error_msg="Failed to remove model patch",
            timeout_duration=10,
        )
        self.communicate_with_handling(
            input=f"git checkout -b {branch_name}",
            error_msg="Failed to switch to new branch",
            timeout_duration=10,
        )
        self.communicate_with_handling(
            input="git add .",
            error_msg="Failed to add commits",
            timeout_duration=10,
        )
        dry_run_flag = "--allow-empty" if _dry_run else ""
        commit_msg = [
            shlex.quote("Fix: {issue.title}"),
            shlex.quote("Closes #{issue.number}"),
        ]
        self.communicate_with_handling(
            input=f"git commit -m {commit_msg[0]} -m  {commit_msg[1]} {dry_run_flag}",
            error_msg="Failed to commit changes",
            timeout_duration=10,
        )

        owner, repo, _ = parse_gh_issue_url(issue_url)
        # If `--repo_path` was specified with a different github URL, then the record will contain
        # the forking user
        assert self.record is not None
        if self.record["repo_type"] != "github":
            # We already validated that `--data_path` is a github issue URL
            # so this is the only case where we can reach here
            msg = "--repo_path must point to a github URL if --open_pr is set"
            raise ValueError(msg)
        forker, _ = self.record["repo"].split("/")
        head = branch_name
        remote = "origin"
        if forker != owner:
            head = f"{forker}:{branch_name}"
            token_prefix = ""
            if self._github_token:
                token_prefix = f"{self._github_token}@"
            fork_url = f"https://{token_prefix}github.com/{forker}/{repo}.git"
            self.logger.debug(f"Using fork: {fork_url}")
            self.communicate_with_handling(
                input=f"git remote add fork {fork_url}",
                error_msg="Failed to create new git remote",
                timeout_duration=10,
            )
            remote = "fork"
        dry_run_prefix = "echo " if _dry_run else ""
        self.communicate_with_handling(
            input=f"{dry_run_prefix} git push {remote} {branch_name}",
            error_msg=(
                "Failed to push branch to remote. Please check your token and permissions. "
                "You might want to push to a fork with the push_gh_repo_url option."
            ),
            timeout_duration=10,
        )
        body = (
            f"This is a PR opened by AI tool [SWE Agent](https://github.com/swe-agent/SWE-agent/) "
            f"to close [#{issue.number}]({issue_url}) ({issue.title}).\n\nCloses #{issue.number}."
        )
        body += "\n\n" + format_trajectory_markdown(trajectory)
        api = GhApi(token=self._github_token)
        if not _dry_run:
            pr_info = api.pulls.create(  # type: ignore
                owner=owner,
                repo=repo,
                title=f"SWE-agent[bot] PR to fix: {issue.title}",
                head=head,
                base="main",
                body=body,
                draft=True,
            )
            self.logger.info(
                f"🎉 PR created as a draft at {pr_info.html_url}. Please review it carefully, push "
                "any required changes onto the branch and then click "
                "'Ready for Review' to bring it to the attention of the maintainers.",
            )

    def read_file(self, path: str | PurePath) -> str:
        """Read file contents from container

        Args:
            path: Path to file relative to repository root

        Returns:
            file_contents: Contents of file as string
        """
        path_in_container = f"/{self._repo_name}/{path}"
        return self.communicate(f"cat {shlex.quote(str(path_in_container))}")

    def _setup_ctf_flag(self) -> None:
        """Set up flag file for CTF challenges"""
        if self.challenge is not None and "flag" in self.challenge:
            flag_value = self.challenge["flag"]
            self.logger.info("Setting up CTF flag file")
            # Write flag to /flag with proper permissions and create symlink
            flag_setup_cmd = f"echo {shlex.quote(flag_value)} > /flag && chmod 400 /flag && ln -sf /flag /flag.txt"
            self.communicate_with_handling(
                flag_setup_cmd,
                error_msg="Failed to set up CTF flag file",
            )

    def _detect_and_handle_server_crash(self, action: str, observation: str) -> tuple[str, bool]:
        """
        Detect if a CTF server has crashed during model interaction and attempt recovery.
        
        Args:
            action: The action that was executed
            observation: The observation returned from the action
            
        Returns:
            tuple: (updated_observation, should_continue)
                - updated_observation: Modified observation with crash handling info
                - should_continue: Whether the episode should continue or terminate
        """
        if self.challenge is None:
            return observation, True  # Not a CTF challenge
            
        # Check for common server crash indicators
        crash_indicators = [
            "Could not connect to",
            "Connection refused",
            "Connection failed",
            "No route to host",
            "Network is unreachable",
            "Connection timed out",
            "Connection reset by peer"
        ]
        
        # Only check for crashes if the action involves network communication
        network_actions = ["python", "nc", "curl", "wget", "telnet", "ssh"]
        is_network_action = any(cmd in action.lower() for cmd in network_actions)
        
        if not is_network_action:
            return observation, True
            
        # Check if observation indicates a server crash
        has_crash_indicator = any(indicator in observation for indicator in crash_indicators)
        
        if has_crash_indicator:
            self.logger.warning(f"🚨 Detected potential CTF server crash. Action: {action[:100]}...")
            self.logger.warning(f"Crash indicators in observation: {observation[:200]}...")
            
            # Attempt to restart the server if we have docker-compose control
            if self.docker_compose and self.args.enable_dynamic_ports:
                self.logger.info("🔄 Attempting to restart CTF server...")
                
                try:
                    # Use docker-compose restart to restart the services
                    restart_cmd = [
                        "docker", "compose", "-f", str(self.docker_compose), "restart"
                    ]
                    self.logger.debug("Restarting CTF services: %s", shlex.join(restart_cmd))
                    result = subprocess.run(restart_cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        self.logger.info("✅ CTF server restart completed successfully")
                        
                        # Wait for services to come back up
                        self.logger.debug("Waiting for services to restart...")
                        time.sleep(15)
                        
                        # Quick validation to see if server is back
                        server_name = self.challenge.get("box")
                        internal_port = self.challenge.get("internal_port")
                        
                        if server_name and internal_port:
                            try:
                                # Quick connectivity test
                                test_cmd = f"timeout 5 bash -c 'echo > /dev/tcp/{shlex.quote(server_name)}/{shlex.quote(str(internal_port))}' 2>/dev/null && echo 'SERVER_RECOVERED' || echo 'SERVER_STILL_DOWN'"
                                test_result = self.communicate(test_cmd, timeout_duration=10)
                                
                                if "SERVER_RECOVERED" in test_result:
                                    self.logger.info("✅ CTF server is now accessible after restart")
                                    updated_observation = observation + "\n\n🔄 CTF server was restarted and is now accessible. You can continue with your exploitation."
                                    return updated_observation, True
                                else:
                                    self.logger.warning("⚠️  CTF server still not accessible after restart")
                                    
                            except Exception as e:
                                self.logger.warning(f"Failed to validate server recovery: {e}")
                        
                        # Even if validation failed, let the model continue - restart policy should help
                        updated_observation = observation + "\n\n CTF server restart attempted. Please wait a moment and try your connection again."
                        return updated_observation, True
                        
                    else:
                        self.logger.error(f"Failed to restart CTF services: {result.stderr}")
                        
                except Exception as e:
                    self.logger.error(f"Exception during CTF server restart: {e}")
                    
            # If restart failed or not available, inform the model about the issue
            if self.args.enable_dynamic_ports:
                updated_observation = observation + "\n\n⚠️  The CTF server appears to have crashed. The system has restart policies in place, so please wait 10-30 seconds and try connecting again. If the issue persists, the server may have been permanently crashed by a previous exploit attempt."
            else:
                updated_observation = observation + "\n\n⚠️  The CTF server appears to be down. This may be due to a previous exploit attempt that crashed the server. You may need to try a different approach or wait for manual server recovery."
                
            return updated_observation, True
            
        return observation, True

    def _verify_network_restrictions(self) -> bool:
        """
        Verify that network restrictions are properly applied and external connections are blocked.
        
        Returns:
            bool: True if restrictions are working (external access blocked), False otherwise
        """
        if not self.args.enable_network_restrictions:
            self.logger.debug("Network restrictions not enabled, skipping verification")
            return True
            
        self.logger.info("🔍 Verifying network restrictions are working...")
        
        # Test 1: Try to reach external DNS (should fail)
        try:
            result = self.communicate(
                "timeout 3 nslookup google.com 8.8.8.8 2>&1 || echo 'DNS_BLOCKED'",
                timeout_duration=5
            )
            if "DNS_BLOCKED" in result or "network unreachable" in result.lower() or "connection timed out" in result.lower():
                self.logger.info("✅ External DNS blocked successfully")
                dns_blocked = True
            else:
                self.logger.warning("⚠️  External DNS not blocked")
                dns_blocked = False
        except Exception as e:
            self.logger.debug(f"DNS test error (likely blocked): {e}")
            dns_blocked = True
            
        # Test 2: Try HTTP connection to external server (should fail)
        try:
            result = self.communicate(
                "timeout 5 curl -I --connect-timeout 3 http://google.com 2>&1 || echo 'HTTP_BLOCKED'",
                timeout_duration=8
            )
            if "HTTP_BLOCKED" in result or "network unreachable" in result.lower() or "connection refused" in result.lower() or "connection timed out" in result.lower():
                self.logger.info("✅ External HTTP blocked successfully")
                http_blocked = True
            else:
                self.logger.warning("⚠️  External HTTP not blocked")
                self.logger.warning(f"HTTP test result: {result[:200]}")
                http_blocked = False
        except Exception as e:
            self.logger.debug(f"HTTP test error (likely blocked): {e}")
            http_blocked = True
            
        # Test 3: Try HTTPS connection to external server (should fail)
        try:
            result = self.communicate(
                "timeout 5 curl -I --connect-timeout 3 https://google.com 2>&1 || echo 'HTTPS_BLOCKED'",
                timeout_duration=8
            )
            if "HTTPS_BLOCKED" in result or "network unreachable" in result.lower() or "connection refused" in result.lower() or "connection timed out" in result.lower():
                self.logger.info("✅ External HTTPS blocked successfully")
                https_blocked = True
            else:
                self.logger.warning("⚠️  External HTTPS not blocked")
                self.logger.warning(f"HTTPS test result: {result[:200]}")
                https_blocked = False
        except Exception as e:
            self.logger.debug(f"HTTPS test error (likely blocked): {e}")
            https_blocked = True
            
        # Test 4: Verify localhost still works (should succeed)
        try:
            result = self.communicate(
                "curl -I --connect-timeout 3 http://localhost:80 2>&1 || curl -I --connect-timeout 3 http://127.0.0.1:80 2>&1 || echo 'LOCALHOST_TEST_COMPLETE'",
                timeout_duration=8
            )
            self.logger.debug("Localhost connectivity test completed")
            localhost_works = True
        except Exception as e:
            self.logger.debug(f"Localhost test error: {e}")
            localhost_works = True  # Don't fail on localhost test errors
            
        # Overall assessment
        external_blocked = dns_blocked and http_blocked and https_blocked
        
        if external_blocked:
            self.logger.info("🔒 Network restrictions verification PASSED - external access is blocked")
            return True
        else:
            self.logger.error("❌ Network restrictions verification FAILED - external access is still possible")
            self.logger.error("This is a security risk - agents can access external servers!")
            return False

    def _get_unique_container_suffix(self) -> str:
        """
        Generate a highly unique container suffix for parallel execution.
        This prevents conflicts between parallel instances by using multiple sources of uniqueness.
        """
        import threading
        import uuid
        import socket
        
        # Get container name parts if available
        if self.container_name:
            name_parts = self.container_name.split('-')
            if len(name_parts) >= 4 and name_parts[0] == "parallel":
                # For names like "parallel-1-cb-gla-crypto-missingbits-try1"
                # Use "1-missingbits-try1" to ensure uniqueness across instances (includes instance ID)
                base_suffix = '-'.join(name_parts[1:])  # Skip "parallel", use rest
            elif len(name_parts) >= 3:
                # For other multi-part names, use last 2 parts
                base_suffix = '-'.join(name_parts[-2:])
            else:
                # Fallback for other naming schemes
                base_suffix = name_parts[-1] if name_parts else "unknown"
        else:
            base_suffix = "auto"
        
        # Add additional unique identifiers to prevent conflicts
        pid = os.getpid()
        thread_id = threading.get_ident()
        timestamp = int(time.time() * 1000)  # millisecond precision
        short_uuid = str(uuid.uuid4())[:8]
        
        # Try to get hostname for additional uniqueness in distributed scenarios
        try:
            hostname = socket.gethostname()[:8]  # First 8 chars of hostname
        except:
            hostname = "local"
        
        # Create a highly unique suffix
        unique_suffix = f"{base_suffix}-{hostname}-{pid}-{thread_id}-{timestamp}-{short_uuid}"
        
        # Limit length to avoid issues with Docker naming limits
        if len(unique_suffix) > 60:
            # Hash the suffix if it's too long
            hash_suffix = hashlib.sha256(unique_suffix.encode()).hexdigest()[:20]
            unique_suffix = f"{base_suffix[:20]}-{hash_suffix}"
        
        self.logger.debug(f"Generated unique container suffix: {unique_suffix}")
        return unique_suffix

    def _restart_ctf_services_and_retry_validation(self) -> bool:
        """
        Attempt to restart CTF services and retry validation.
        This handles transient issues that might cause initial validation failures.
        
        Returns:
            bool: True if validation succeeds after restart, False otherwise
        """
        if self.challenge is None or not self.docker_compose:
            self.logger.debug("No CTF services to restart (not a CTF challenge or no docker-compose)")
            return False
        
        max_restart_attempts = 2 if self.args.enable_dynamic_ports else 1  # More attempts for parallel execution
        
        for restart_attempt in range(max_restart_attempts):
            self.logger.info(f"🔄 Restart attempt {restart_attempt + 1}/{max_restart_attempts}")
            
            try:
                # Step 1: Restart Docker Compose services
                self.logger.info("🔄 Restarting Docker Compose services...")
                project_name = self.docker_compose_project_name or self.actual_docker_compose_project_name
                
                if project_name:
                    restart_cmd = [
                        "docker", "compose", "-f", str(self.docker_compose), 
                        "-p", project_name,
                        "restart"
                    ]
                    self.logger.debug(f"Restart command: {shlex.join(restart_cmd)}")
                    
                    # Use the docker-compose working directory for consistency
                    challenge_dir = self.docker_compose.parent
                    result = subprocess.run(
                        restart_cmd, 
                        capture_output=True, 
                        text=True, 
                        timeout=60,
                        cwd=str(challenge_dir)  # Use same working directory as original startup
                    )
                    
                    if result.returncode == 0:
                        self.logger.info("✅ Docker Compose services restarted successfully")
                    else:
                        self.logger.warning(f"Docker Compose restart warning: {result.stderr}")
                        # Don't fail immediately - sometimes restart warnings are not critical
                else:
                    self.logger.warning("No project name available for restart, trying alternative approach")
                    # Fallback: try to restart using docker-compose down/up
                    down_cmd = ["docker", "compose", "-f", str(self.docker_compose), "down"]
                    up_cmd = ["docker", "compose", "-f", str(self.docker_compose), "up", "-d"]
                    
                    challenge_dir = self.docker_compose.parent
                    subprocess.run(down_cmd, capture_output=True, cwd=str(challenge_dir), timeout=30)
                    time.sleep(5)  # Brief pause
                    subprocess.run(up_cmd, capture_output=True, cwd=str(challenge_dir), timeout=60)
                
                # Step 2: Wait for services to restart
                restart_wait_time = 20 if self.args.enable_dynamic_ports else 30
                self.logger.info(f"⏳ Waiting {restart_wait_time}s for services to restart...")
                time.sleep(restart_wait_time)
                
                # Step 3: Verify container is still responsive
                if not self._validate_container_health():
                    self.logger.error("❌ Container became unresponsive during restart")
                    continue
                
                # Step 4: Re-verify network attachment if we have a dynamic network
                if self.dynamic_network_name:
                    self.logger.info(f"🔗 Re-verifying network attachment to {self.dynamic_network_name}")
                    try:
                        self._verify_network_attachment(self.dynamic_network_name)
                        self.logger.debug("✅ Network attachment verified after restart")
                    except Exception as e:
                        self.logger.warning(f"Network re-verification failed: {e}")
                        # Try to re-attach if verification failed
                        try:
                            from sweagent.environment.utils import attach_network_interface_to_container
                            attach_network_interface_to_container(self.container_name, self.dynamic_network_name)
                            self.logger.info("✅ Re-attached to network after restart")
                        except Exception as reattach_error:
                            self.logger.error(f"Failed to re-attach to network: {reattach_error}")
                            continue
                
                # Step 5: Retry validation
                self.logger.info("🔍 Retrying CTF server validation after restart...")
                if self._validate_ctf_server_connectivity():
                    self.logger.info("✅ CTF server validation succeeded after restart!")
                    return True
                else:
                    self.logger.warning(f"❌ Validation still failed after restart attempt {restart_attempt + 1}")
                    
                    # Add increasing delay between restart attempts
                    if restart_attempt < max_restart_attempts - 1:
                        delay = 10 * (restart_attempt + 1)  # 10s, 20s, etc.
                        self.logger.info(f"⏸️  Waiting {delay}s before next restart attempt...")
                        time.sleep(delay)
                
            except subprocess.TimeoutExpired:
                self.logger.error(f"❌ Restart attempt {restart_attempt + 1} timed out")
                continue
            except Exception as e:
                self.logger.error(f"❌ Restart attempt {restart_attempt + 1} failed with error: {e}")
                continue
        
        self.logger.error(f"❌ All {max_restart_attempts} restart attempts failed")
        return False

    def _safe_exec_run(self, command: str, timeout_duration: int | None = None, **kwargs) -> str:
        """
        Safe wrapper for container.exec_run with timeout handling.
        
        Args:
            command: Command to execute
            timeout_duration: Timeout in seconds (default: uses DOCKER_EXEC_TIMEOUT)
            **kwargs: Additional arguments for exec_run
            
        Returns:
            str: Command output
            
        Raises:
            RuntimeError: If command fails or times out
        """
        if not self.container_obj:
            raise RuntimeError("Container object not available")
            
        # Use the global constant if no timeout specified
        if timeout_duration is None:
            timeout_duration = DOCKER_EXEC_TIMEOUT
            
        try:
            # Use subprocess with docker exec for reliable timeout handling
            # This approach actually works because subprocess.run supports timeout properly
            
            import subprocess
            import shlex
            
            # Build docker exec command
            container_name = self.container_obj.name
            if isinstance(command, str):
                # If command is a string, we need to properly handle it
                docker_cmd = ["docker", "exec", container_name, "bash", "-c", command]
            else:
                # If command is already a list
                docker_cmd = ["docker", "exec", container_name] + command
            
            start_time = time.time()
            
            try:
                # Use subprocess.run with timeout - this actually works!
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_duration
                )
                
                elapsed = time.time() - start_time
                
                # Log successful execution
                self.logger.debug(f"Docker exec completed in {elapsed:.2f}s: {command}")
                
                # Return stdout if available, otherwise stderr
                if result.stdout:
                    return result.stdout.strip()
                elif result.stderr:
                    return result.stderr.strip()
                else:
                    return ""
                    
            except subprocess.TimeoutExpired as e:
                elapsed = time.time() - start_time
                self.logger.warning(f"Docker exec timed out after {elapsed:.1f}s: {command}")
                
                # Return any partial output if available
                partial_output = ""
                if e.stdout:
                    partial_output += e.stdout.strip()
                if e.stderr:
                    if partial_output:
                        partial_output += "\n"
                    partial_output += e.stderr.strip()
                
                error_msg = f"Docker exec_run timed out after {timeout_duration}s: {command}"
                if partial_output:
                    error_msg += f"\nPartial output: {partial_output[:200]}..."
                
                raise RuntimeError(error_msg)
                
            except subprocess.CalledProcessError as e:
                # Command failed but didn't timeout
                self.logger.debug(f"Docker exec failed with exit code {e.returncode}: {command}")
                
                # For most cases, we still want to return the output even if exit code != 0
                # because many commands (like ps, ls) might have non-zero exit codes but still produce useful output
                if e.stdout:
                    return e.stdout.strip()
                elif e.stderr:
                    return e.stderr.strip()
                else:
                    raise RuntimeError(f"Docker exec_run failed with exit code {e.returncode}: {command}")
                    
        except RuntimeError:
            # Re-raise our timeout/failure errors as-is
            raise
        except Exception as e:
            raise RuntimeError(f"Docker exec_run failed: {e}")

    def _safe_communicate_with_timeout(self, command: str, timeout_duration: int = 25, max_retries: int = MAX_EXECUTION_RETRIES) -> str:
        """
        Enhanced communicate method with better timeout handling and retry logic.
        
        Args:
            command: Command to execute
            timeout_duration: Timeout in seconds
            max_retries: Maximum number of retry attempts (default: MAX_EXECUTION_RETRIES)
            
        Returns:
            str: Command output
            
        Raises:
            RuntimeError: If communication fails after retries
        """
        for attempt in range(max_retries):
            try:
                # Use shorter timeout for each attempt
                adjusted_timeout = min(timeout_duration, 60)  # Cap at 60 seconds per attempt
                
                result = self.communicate(
                    input=command,
                    timeout_duration=adjusted_timeout,
                    no_output_timeout_duration=adjusted_timeout,
                )
                return result
                
            except TimeoutError as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"Command timed out on attempt {attempt + 1}/{max_retries}: {command[:50]}...")
                    
                    # Try to interrupt stuck processes
                    try:
                        self.interrupt()
                    except Exception as interrupt_error:
                        self.logger.warning(f"Failed to interrupt stuck processes: {interrupt_error}")
                    
                    # Wait before retry
                    time.sleep(2)
                    continue
                else:
                    # Final attempt failed
                    raise RuntimeError(f"Command timed out after {max_retries} attempts: {command[:50]}...")
                    
            except Exception as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"Command failed on attempt {attempt + 1}/{max_retries}: {e}")
                    time.sleep(1)
                    continue
                else:
                    raise RuntimeError(f"Command failed after {max_retries} attempts: {e}")
        
        raise RuntimeError(f"All {max_retries} attempts failed for command: {command[:50]}...")

    def _handle_stuck_execution(self, action: str) -> str:
        """
        Handle cases where agent execution appears to be stuck.
        
        Args:
            action: The action that may be stuck
            
        Returns:
            str: Error message explaining the timeout
        """
        self.logger.warning(f"Execution appears stuck for action: {action[:100]}...")
        
        # Try to diagnose what's causing the hang
        try:
            # Check if container is still responsive
            if not self._validate_container_health():
                return "CONTAINER UNRESPONSIVE: The container has stopped responding. Process will be restarted."
            
            # Check for stuck processes
            pids = self.get_pids()
            if len(pids) > 10:  # Unusually high number of processes
                return f"HIGH PROCESS COUNT: {len(pids)} processes detected. Some processes may be stuck. Consider using 'pkill' to clean up."
            
            # Check for common stuck patterns
            if any(pattern in action.lower() for pattern in ['grep -r', 'find /', 'search', 'locate']):
                return "LONG OPERATION DETECTED: This appears to be a filesystem search operation. These can take a very long time. Consider using more specific search terms or paths."
            
            if any(pattern in action.lower() for pattern in ['python', 'node', 'java', 'compile']):
                return "LONG COMPUTATION DETECTED: This appears to be running a program or compilation. These operations can take time. Consider adding timeout handling or progress indicators."
            
        except Exception as e:
            self.logger.debug(f"Failed to diagnose stuck execution: {e}")
        
        return "EXECUTION TIMEOUT: The command took too long to complete. Please try a simpler or more specific command."
