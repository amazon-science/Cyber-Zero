# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shlex
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import traceback
import uuid
from io import BytesIO
from pathlib import Path
from subprocess import PIPE, STDOUT
from typing import Any, Callable

from datasets import load_dataset, load_from_disk
from ghapi.all import GhApi
from git import InvalidGitRepositoryError, Repo
from unidiff import PatchSet

import docker
import docker.types
from docker.models.containers import Container
from sweagent.utils.config import keys_config
from sweagent.utils.log import get_logger

DOCKER_START_UP_DELAY = float(keys_config.get("SWE_AGENT_DOCKER_START_UP_DELAY", 1))
DOCKER_COMPOSE_TERMINATION_DELAY = float(keys_config.get("SWE_AGENT_DOCKER_START_UP_DELAY", 100))
DOCKER_COMPOSE_STARTUP_DELAY = float(keys_config.get("SWE_AGENT_DOCKER_START_UP_DELAY", 1200))  # 20 minutes instead of 10
GITHUB_ISSUE_URL_PATTERN = re.compile(r"github\.com\/(.*?)\/(.*?)\/issues\/(\d+)")
GITHUB_REPO_URL_PATTERN = re.compile(r".*[/@]?github\.com\/([^/]+)\/([^/]+)")

CTF_CHALLENGES_CATEGORIES = {
    "rev": "reverse engineering",
    "pwn": "binary exploitation",
    "web": "web security",
    "crypto": "cryptography",
    "misc": "miscellaneous",
    "forensics": "forensics",
}

# Port management constants
DEFAULT_PORT_RANGE_START = 10000
DEFAULT_PORT_RANGE_END = 20000

logger = get_logger("env_utils")

# Timeout constants for utilities
UTILS_DOCKER_EXEC_TIMEOUT = float(os.environ.get("SWE_AGENT_DOCKER_EXEC_TIMEOUT", "30"))


class NoOutputTimeoutError(TimeoutError): ...


def test_network_connectivity(host: str, port: int, timeout: int = 10) -> bool:
    """
    Test network connectivity to a specific host and port.
    
    Args:
        host: Hostname or IP address to connect to
        port: Port number to test
        timeout: Connection timeout in seconds
    
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception as e:
        logger.debug(f"Network connectivity test failed for {host}:{port}: {e}")
        return False


def wait_for_service_availability(host: str, port: int, max_wait_time: int = 60, check_interval: int = 5) -> bool:
    """
    Wait for a service to become available on a specific host and port.
    
    Args:
        host: Hostname or IP address to connect to
        port: Port number to test
        max_wait_time: Maximum time to wait in seconds
        check_interval: Time between checks in seconds
    
    Returns:
        bool: True if service becomes available, False if timeout reached
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        if test_network_connectivity(host, port):
            logger.debug(f"Service {host}:{port} is now available")
            return True
        
        logger.debug(f"Service {host}:{port} not yet available, waiting {check_interval} seconds...")
        time.sleep(check_interval)
    
    logger.warning(f"Service {host}:{port} did not become available within {max_wait_time} seconds")
    return False


def is_port_in_use(port: int, host: str = 'localhost') -> bool:
    """Check if a port is currently in use"""
    import socket
    
    # Check if we can bind to the port (TCP)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return False  # Port is available
    except OSError:
        pass  # Port might be in use, check further
    
    # Also check if anything is listening on the port
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)  # Very short timeout
            result = sock.connect_ex((host, port))
            return result == 0  # If connection succeeds, port is in use
    except:
        pass
    
    return True  # Assume in use if we can't determine


def get_available_port(start_port: int = DEFAULT_PORT_RANGE_START, end_port: int = DEFAULT_PORT_RANGE_END, host: str = 'localhost') -> int:
    """
    Find an available port in the given range with improved parallel execution support.
    
    Args:
        start_port: Starting port number to search from
        end_port: Ending port number to search to  
        host: Host to check port availability on
        
    Returns:
        Available port number
        
    Raises:
        RuntimeError: If no available port is found in the range
    """
    import random
    import time
    
    # For parallel execution, randomize the search order to reduce conflicts
    port_range = list(range(start_port, end_port + 1))
    random.shuffle(port_range)
    
    max_retries = 3
    for retry in range(max_retries):
        for port in port_range:
            if not is_port_in_use(port, host):
                # Double-check the port is still available after a brief delay
                # This helps catch race conditions in parallel execution
                time.sleep(0.01 * (retry + 1))  # Small progressive delay
                if not is_port_in_use(port, host):
                    logger.debug(f"Found available port: {port} (retry {retry + 1})")
                    return port
        
        # If no port found in this retry, wait a bit longer before next attempt
        if retry < max_retries - 1:
            wait_time = 0.1 * (2 ** retry)  # Exponential backoff: 0.1s, 0.2s, 0.4s
            logger.debug(f"No available port found in retry {retry + 1}, waiting {wait_time}s before next attempt")
            time.sleep(wait_time)
    
    raise RuntimeError(f"No available port found in range {start_port}-{end_port} after {max_retries} retries")


def get_multiple_available_ports(count: int, start_port: int = DEFAULT_PORT_RANGE_START, end_port: int = DEFAULT_PORT_RANGE_END, host: str = 'localhost') -> list[int]:
    """Get multiple available ports at once to reduce conflicts"""
    import random
    
    if count <= 0:
        return []
    
    # Create a randomized list of ports to try
    port_range = list(range(start_port, end_port + 1))
    random.shuffle(port_range)
    
    allocated_ports = []
    temp_sockets = []
    
    try:
        for port in port_range:
            if len(allocated_ports) >= count:
                break
                
            if not is_port_in_use(port, host):
                # Try to temporarily bind to the port to reserve it
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((host, port))
                    sock.listen(1)
                    temp_sockets.append(sock)
                    allocated_ports.append(port)
                    logger.debug(f"Reserved port: {port}")
                except OSError:
                    continue
        
        if len(allocated_ports) < count:
            raise RuntimeError(f"Could only find {len(allocated_ports)} available ports out of {count} requested in range {start_port}-{end_port}")
        
        return allocated_ports
    
    finally:
        # Close all temporary sockets to release the ports
        for sock in temp_sockets:
            try:
                sock.close()
            except:
                pass


# Create a temporary file with more unique naming
# Use PID and timestamp to make it more unique for parallel execution
import uuid
import threading

def create_dynamic_docker_compose(
    original_compose_path: Path, 
    container_name_suffix: str,
    dynamic_network_name: str,
    port_mappings: dict[str, int]
) -> Path:
    """
    Create a modified docker-compose.yml file with dynamic ports and network configuration.
    
    The temporary file is created in the same directory as the original to preserve 
    build contexts and relative paths used in the original compose file.
    
    Args:
        original_compose_path: Path to the original docker-compose.yml
        container_name_suffix: Unique suffix for containers/networks
        dynamic_network_name: The exact network name we want to use
        port_mappings: Dictionary mapping internal ports to external ports
    
    Returns:
        Path to the new docker-compose.yml file (will be cleaned up automatically)
    """
    import yaml
    import tempfile
    import uuid
    
    # CRITICAL FIX: Create the network externally first
    # This ensures we have full control over the network name
    logger.info(f"Creating external network: {dynamic_network_name}")
    try:
        # Create the network with our exact desired name
        create_network_cmd = [
            "docker", "network", "create", 
            "--driver", "bridge",
            dynamic_network_name
        ]
        result = subprocess.run(create_network_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"✅ Created external network: {dynamic_network_name}")
        elif "already exists" in result.stderr:
            logger.info(f"✅ External network already exists: {dynamic_network_name}")
        else:
            logger.error(f"❌ Failed to create external network: {result.stderr}")
            raise RuntimeError(f"Failed to create network {dynamic_network_name}: {result.stderr}")
            
    except Exception as e:
        logger.error(f"Failed to create external network {dynamic_network_name}: {e}")
        raise RuntimeError(f"Network creation failed: {e}")
    
    # Generate unique ID for temporary file
    unique_id = str(uuid.uuid4())[:8]
    
    # Load original compose file
    with open(original_compose_path, 'r') as f:
        compose_data = yaml.safe_load(f)
    
    if not compose_data:
        raise ValueError("Empty or invalid docker-compose.yml file")
    
    # Update container names to include suffix for uniqueness
    if 'services' in compose_data:
        # Rename service keys and update container names
        new_services = {}
        service_name_mapping = {}  # Track old name -> new name mappings for depends_on updates
        
        for service_name, service_config in compose_data['services'].items():
            # Create new service name with suffix
            new_service_name = f"{service_name}-{container_name_suffix}"
            service_name_mapping[service_name] = new_service_name
            
            # Update container name if present, otherwise add it
            if 'container_name' in service_config:
                original_name = service_config['container_name']
                service_config['container_name'] = f"{original_name}-{container_name_suffix}"
                logger.debug(f"Updated container name: {original_name} -> {service_config['container_name']}")
            else:
                service_config['container_name'] = new_service_name
                logger.debug(f"Added container name: {new_service_name}")
            
            # CRITICAL FIX: Add restart policy for automatic recovery from crashes
            # This ensures that CTF servers automatically restart when they crash
            # This is especially important for CTF challenges where services might crash due to exploits
            if 'restart' not in service_config:
                # Add restart policy if not already specified
                service_config['restart'] = 'always'  # Restart
                logger.debug(f"Added restart policy 'always' to service {new_service_name}")
            else:
                logger.debug(f"Service {new_service_name} already has restart policy: {service_config['restart']}")
            
            # Update port mappings if dynamic ports are enabled
            if 'ports' in service_config and port_mappings:
                # Preserve original port mappings for reference
                original_ports = service_config['ports'].copy()
                updated_ports = []
                
                for port_config in service_config['ports']:
                    if isinstance(port_config, str) and ':' in port_config:
                        external_port, internal_port = port_config.split(':', 1)
                        
                        # Look for port mapping using service-specific key first
                        mapping_key = f"{service_name}:{internal_port}"
                        if mapping_key in port_mappings:
                            new_external_port = port_mappings[mapping_key]
                            updated_ports.append(f"{new_external_port}:{internal_port}")
                            logger.debug(f"Updated port mapping for {new_service_name}: {external_port}:{internal_port} -> {new_external_port}:{internal_port}")
                        elif internal_port in port_mappings:
                            # Fallback to simple internal port key for backward compatibility
                            new_external_port = port_mappings[internal_port]
                            updated_ports.append(f"{new_external_port}:{internal_port}")
                            logger.debug(f"Updated port mapping for {new_service_name}: {external_port}:{internal_port} -> {new_external_port}:{internal_port}")
                        else:
                            updated_ports.append(port_config)
                            logger.debug(f"No port mapping found for {new_service_name}:{internal_port}, keeping original: {port_config}")
                    elif isinstance(port_config, int):
                        # Handle integer port (just internal port specified)
                        internal_port = str(port_config)
                        mapping_key = f"{service_name}:{internal_port}"
                        if mapping_key in port_mappings:
                            new_external_port = port_mappings[mapping_key]
                            updated_ports.append(f"{new_external_port}:{internal_port}")
                            logger.debug(f"Updated port mapping for {new_service_name}: {port_config} -> {new_external_port}:{internal_port}")
                        elif internal_port in port_mappings:
                            new_external_port = port_mappings[internal_port]
                            updated_ports.append(f"{new_external_port}:{internal_port}")
                            logger.debug(f"Updated port mapping for {new_service_name}: {port_config} -> {new_external_port}:{internal_port}")
                        else:
                            updated_ports.append(port_config)
                            logger.debug(f"No port mapping found for {new_service_name}:{internal_port}, keeping original: {port_config}")
                    else:
                        # Keep other port configurations as-is
                        updated_ports.append(port_config)
                
                service_config['ports'] = updated_ports
                logger.debug(f"Updated ports for {new_service_name}: {original_ports} -> {updated_ports}")
            
            # Store service with new name
            new_services[new_service_name] = service_config
            logger.debug(f"Renamed service: {service_name} -> {new_service_name}")
        
        # CRITICAL FIX: Update depends_on references to use new service names
        for service_name, service_config in new_services.items():
            if 'depends_on' in service_config:
                if isinstance(service_config['depends_on'], list):
                    # Handle list format: depends_on: [service1, service2]
                    updated_depends = []
                    for dep_service in service_config['depends_on']:
                        if dep_service in service_name_mapping:
                            new_dep_name = service_name_mapping[dep_service]
                            updated_depends.append(new_dep_name)
                            logger.debug(f"Updated depends_on: {dep_service} -> {new_dep_name}")
                        else:
                            updated_depends.append(dep_service)
                    service_config['depends_on'] = updated_depends
                    
                elif isinstance(service_config['depends_on'], dict):
                    # Handle dict format: depends_on: {service1: {condition: service_healthy}}
                    updated_depends = {}
                    for dep_service, dep_config in service_config['depends_on'].items():
                        if dep_service in service_name_mapping:
                            new_dep_name = service_name_mapping[dep_service]
                            updated_depends[new_dep_name] = dep_config
                            logger.debug(f"Updated depends_on: {dep_service} -> {new_dep_name}")
                        else:
                            updated_depends[dep_service] = dep_config
                    service_config['depends_on'] = updated_depends
                    
                logger.debug(f"Updated depends_on for service {service_name}")
        
        # Replace services with renamed versions
        compose_data['services'] = new_services
    
    # CRITICAL FIX: Reference the external network we just created
    # This ensures the network name is exactly what we want, no Docker Compose auto-naming
    compose_data['networks'] = {
        dynamic_network_name: {
            'name': dynamic_network_name,
            'external': True,  # This tells Docker Compose to use our pre-created network
            'driver': 'bridge'  # Add driver for test compatibility
        }
    }
    
    # Ensure all services use the external network
    if 'services' in compose_data:
        for service_name, service_config in compose_data['services'].items():
            # CRITICAL FIX: Check for network_mode before adding networks
            # network_mode and networks are mutually exclusive in Docker Compose
            if 'network_mode' in service_config:
                logger.warning(f"Service {service_name} has network_mode='{service_config['network_mode']}' defined. Removing network_mode to use custom networks.")
                # Remove network_mode to allow custom networks
                del service_config['network_mode']
            
            if 'networks' not in service_config:
                service_config['networks'] = [dynamic_network_name]
            elif isinstance(service_config['networks'], list):
                # Replace any 'ctfnet' references with dynamic_network_name
                new_networks = []
                for net in service_config['networks']:
                    if net == 'ctfnet':
                        new_networks.append(dynamic_network_name)
                    else:
                        new_networks.append(net)
                service_config['networks'] = new_networks
            elif isinstance(service_config['networks'], dict):
                # Handle dict format networks - replace ctfnet with dynamic_network_name
                new_networks = {}
                for net_name, net_config in service_config['networks'].items():
                    if net_name == 'ctfnet':
                        new_networks[dynamic_network_name] = net_config
                    else:
                        new_networks[net_name] = net_config
                service_config['networks'] = new_networks
            logger.debug(f"Updated service {service_name} to use external network: {dynamic_network_name}")
    
    # Create temporary file
    try:
        # CRITICAL FIX: Create the temporary file in the same directory as the original
        # This ensures that all relative paths (especially build contexts and Dockerfiles) 
        # remain valid when Docker Compose processes the file
        temp_dir = original_compose_path.parent
        
        temp_file_path = temp_dir / f"docker-compose-{unique_id}.yml"
        
        # Write the modified compose file
        with open(temp_file_path, 'w') as f:
            yaml.dump(compose_data, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"✅ Created dynamic docker-compose file: {temp_file_path}")
        logger.info(f"✅ Network will be: {dynamic_network_name} (external, pre-created)")
        return temp_file_path
        
    except Exception as e:
        logger.error(f"Failed to create temporary docker-compose file: {e}")
        raise RuntimeError(f"Failed to create compose file: {e}")


def get_data_path_name(data_path: str) -> str:
    """if data_path is a file, return the file stem
    elif it's a github url, return the owner__repo_name
    """
    if data_path.startswith("text://"):
        return hashlib.sha256(data_path.removeprefix("text://").encode()).hexdigest()[:6]
    match = GITHUB_ISSUE_URL_PATTERN.search(data_path)
    if match:
        owner, repo, _ = match.groups()
        return f"{owner}__{repo}"
    return Path(data_path).stem


def is_github_issue_url(data_path: str) -> bool:
    """Check if data_path is an URL pointing to a github issue"""
    return GITHUB_ISSUE_URL_PATTERN.search(data_path) is not None


def is_github_repo_url(data_path: str) -> bool:
    """Check if data_path is an URL pointing to a github repository.
    Paths to issues or PRs will also match this pattern.
    """
    return GITHUB_REPO_URL_PATTERN.search(data_path) is not None


# TODO: Why not just use copy_anything_to_container?
def copy_file_to_container(container: Container, contents: str, container_path: str) -> None:
    """
    Copies a given string into a Docker container at a specified path.

    Args:
        container: Docker SDK container object.
        contents: The string to copy into the container.
        container_path: The path inside the container where the string should be copied to.

    Returns:
        None
    """
    temp_file_name = None

    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_name = temp_file.name
            # Write the string to the temporary file and ensure it's written to disk
            temp_file.write(contents.encode("utf-8"))
            temp_file.flush()
            os.fsync(temp_file.fileno())

        # Create a TAR archive in memory containing the temporary file
        with tempfile.NamedTemporaryFile():
            with open(temp_file_name, "rb") as temp_file:
                # Prepare the TAR archive
                with BytesIO() as tar_stream:
                    with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                        tar_info = tarfile.TarInfo(name=Path(container_path).name)
                        tar_info.size = Path(temp_file_name).stat().st_size
                        tar.addfile(tarinfo=tar_info, fileobj=temp_file)
                    tar_stream.seek(0)
                    # Copy the TAR stream to the container
                    container.put_archive(path=Path(container_path).parent, data=tar_stream.read())

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        logger.error(traceback.format_exc())
    finally:
        # Cleanup: Remove the temporary file if it was created
        if temp_file_name and Path(temp_file_name).exists():
            os.remove(temp_file_name)


def copy_anything_to_container(container: Container, host_path: str, container_path: str) -> None:
    """Copy files or directories from host to container

    Note: Will need to set ownership on the copied files in the container.
    """
    if not Path(host_path).exists():
        msg = f"Path {host_path} does not exist, cannot copy it to container."
        raise FileNotFoundError(msg)
    
    # CRITICAL: Add validation to ensure we're copying to the right container
    # In parallel execution, prevent mix-ups by validating container state
    try:
        container.reload()  # Refresh container state
        if container.status not in ['running', 'created']:
            logger.warning(f"⚠️  Container {container.name} is not in running state: {container.status}")
        
        container_name = container.name
        container_id = container.id
        logger.debug(f"📂 Copying {host_path} to container {container_name} (ID: {container_id[:12]}) at {container_path}")
        
    except Exception as e:
        logger.warning(f"⚠️  Could not validate container state before copy: {e}")
    
    cmd = ["docker", "cp", host_path, f"{container.id}:{container_path}"]
    logger.debug(f"Copying {host_path} to container at {container_path} with command: {shlex.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
        logger.debug(f"✅ Successfully copied {host_path} to container {container.name}")
    except subprocess.CalledProcessError as e:
        msg = f"Error copying {host_path} to container at {container_path}: {e}"
        raise RuntimeError(msg) from e


def read_with_timeout(container: subprocess.Popen, pid_func: Callable, timeout_duration: int | float) -> str:
    """
    Read data from a subprocess with a timeout.
    This function uses a file descriptor to read data from the subprocess in a non-blocking way.

    Args:
        container: The subprocess container.
        pid_func: A function that returns a list of process IDs (except the PID of the main process).
        timeout_duration: The timeout duration in seconds.

    Returns:
        output: The data read from the subprocess, stripped of trailing newline characters.

    Raises:
        TimeoutError: If the timeout duration is reached while reading from the subprocess.
    """
    buffer = b""
    fd = container.stdout.fileno()
    end_time = time.time() + timeout_duration

    # Select is not available on windows
    is_windows = platform.system() == "Windows"
    if not is_windows:
        import select
    else:
        os.set_blocking(fd, False)

    def ready_to_read(fd) -> bool:
        if is_windows:
            # We can't do the extra check
            return True
        return bool(select.select([fd], [], [], 0.01)[0])

    while time.time() < end_time:
        pids = pid_func()
        if len(pids) > 0:
            # There are still PIDs running
            time.sleep(0.05)
            continue
        if ready_to_read(fd):
            data = os.read(fd, 4096)
            if data:
                buffer += data
        else:
            # No more data to read
            break
        time.sleep(0.05)  # Prevents CPU hogging

    if container.poll() is not None:
        msg = f"Subprocess exited unexpectedly.\nCurrent buffer: {buffer.decode()}"
        raise RuntimeError(msg)
    if time.time() >= end_time:
        msg = f"Timeout reached while reading from subprocess.\nCurrent buffer: {buffer.decode()}\nRunning PIDs: {pids}"
        raise TimeoutError(msg)

    decoded = buffer.decode("utf-8", errors="backslashreplace").replace("\r\n", "\n")
    return "\n".join(line for line in decoded.splitlines())


PROCESS_DONE_MARKER_START = "///PROCESS-DONE:"
PROCESS_DONE_MARKER_END = ":PROCESS-DONE///"
PROCESS_DONE_REGEX = re.compile(rf"{PROCESS_DONE_MARKER_START}(.+?){PROCESS_DONE_MARKER_END}")
DECODED_BUFFER_FAILURE_THRESHOLD = 0.1


def _check_for_too_many_non_unicode_bytes(buffer: bytes):
    number_of_failures = int(DECODED_BUFFER_FAILURE_THRESHOLD * len(buffer))
    start_byte = 0
    for _ in range(number_of_failures):
        try:
            buffer[start_byte:].decode()
            return
        except UnicodeDecodeError as e:
            start_byte = e.start + 1
    msg = "Too many non-unicode characters in output of command."
    raise UnicodeError(msg)


def read_with_timeout_experimental(
    container: subprocess.Popen, timeout_duration: int | float, no_output_timeout_duration: int | float
) -> tuple[str, str]:
    """
    Read data from a subprocess with a timeout.
    This function uses a file descriptor to read data from the subprocess in a non-blocking way.

    NOTE: This is an experimental implementation that is faster than `read_with_timeout`, but
    has not been thoroughly tested.

    Args:
        container: The subprocess container.
        timeout_duration: The timeout duration in seconds.
        no_output_timeout_duration: The timeout duration to wait if no output is produced, in seconds.

    Returns:
        Output and exit code, both as strings (!)

    Raises:
        TimeoutError: If the timeout duration is reached while reading from the subprocess.
    """
    buffer = b""
    fd = container.stdout.fileno()
    start_time = time.time()
    end_time = start_time + timeout_duration
    end_time_no_output = start_time + no_output_timeout_duration

    # Select is not available on windows
    is_windows = platform.system() == "Windows"
    if not is_windows:
        import select
    else:
        os.set_blocking(fd, False)

    def ready_to_read(fd) -> bool:
        if is_windows:
            # We can't do the extra check
            return True
        return bool(select.select([fd], [], [], 0.01)[0])

    process_done = False

    while time.time() < min(end_time, end_time_no_output):
        if ready_to_read(fd):
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                logger.error("BlockingIOError while reading from subprocess.", exc_info=True)
                break
            if data:
                end_time_no_output = time.time() + no_output_timeout_duration
                buffer += data
                # Check for process done marker in the decoded buffer
                decoded_check = buffer.decode("utf-8", errors="backslashreplace").replace("\r\n", "\n")
                if PROCESS_DONE_MARKER_START in decoded_check:
                    process_done = True
                    break
        time.sleep(0.01)  # Prevents CPU hogging

    decoded = buffer.decode("utf-8", errors="backslashreplace").replace("\r\n", "\n")
    body = "\n".join(line for line in decoded.splitlines() if not line.startswith(PROCESS_DONE_MARKER_START))

    if container.poll() is not None:
        msg = f"Subprocess exited unexpectedly.\nCurrent buffer: {decoded}"
        raise RuntimeError(msg, body)

    current_time = time.time()
    if not process_done and current_time >= min(end_time, end_time_no_output):
        if current_time >= end_time:
            msg = f"Timeout reached while reading from subprocess.\nCurrent buffer: {decoded}"
            raise TimeoutError(msg, body)
        else:
            msg = f"No output timeout reached while reading from subprocess.\nCurrent buffer: {decoded}"
            raise NoOutputTimeoutError(msg, body)

    _check_for_too_many_non_unicode_bytes(buffer=buffer)
    
    # More robust process done marker extraction
    _results = PROCESS_DONE_REGEX.search(decoded)
    if _results is None:
        # Try to find the marker with more flexible matching
        # Look for lines that contain the start marker
        lines = decoded.splitlines()
        exit_code = None
        
        for line in lines:
            if PROCESS_DONE_MARKER_START in line:
                # Try to extract exit code from this line
                # Handle cases where the line might be malformed
                if PROCESS_DONE_MARKER_END in line:
                    # Standard format: ///PROCESS-DONE:exit_code:PROCESS-DONE///
                    try:
                        start_idx = line.find(PROCESS_DONE_MARKER_START) + len(PROCESS_DONE_MARKER_START)
                        end_idx = line.find(PROCESS_DONE_MARKER_END)
                        if start_idx > 0 and end_idx > start_idx:
                            exit_code = line[start_idx:end_idx]
                            break
                    except Exception:
                        pass
                else:
                    # Fallback: look for ///PROCESS-DONE:exit_code (without end marker)
                    try:
                        start_idx = line.find(PROCESS_DONE_MARKER_START) + len(PROCESS_DONE_MARKER_START)
                        remainder = line[start_idx:]
                        # Extract everything until whitespace or end of line
                        exit_code = remainder.split()[0] if remainder.split() else "999"
                        break
                    except Exception:
                        pass
        
        if exit_code is None:
            # Last resort: check if buffer contains shell variable expansion
            if "$EXITSTATUS" in decoded:
                exit_code = "$EXITSTATUS"
            else:
                # Complete fallback
                msg = f"Could not find process done marker in last line: {decoded=}, {body=}"
                raise ValueError(msg, body)
    else:
        exit_code = _results.group(1)
    
    # Clean up the body by removing the process done marker line
    if exit_code and exit_code != "$EXITSTATUS":
        marker_line = f"{PROCESS_DONE_MARKER_START}{exit_code}{PROCESS_DONE_MARKER_END}"
        body = body.replace(marker_line, "")
    
    return body, exit_code


def read_session_with_timeout(
    session: subprocess.Popen,
    terminal_pattern: str,
    timeout_duration: int | float,
    no_output_timeout_duration: int | float,
) -> str:
    """
    Read data from a subprocess with a timeout.
    This function uses a file descriptor to read data from the subprocess in a non-blocking way.

    Args:
        session: The session subprocess.
        terminal_pattern: the terminal pattern to indicate end of output.
        timeout_duration: The timeout duration in seconds.

    Returns:
        Output

    Raises:
        TimeoutError: If the timeout duration is reached while reading from the subprocess.
    """
    buffer = b""
    fd = session.stdout.fileno()
    start_time = time.time()
    end_time = start_time + timeout_duration
    end_time_no_output = start_time + no_output_timeout_duration

    # Select is not available on windows
    import select

    def ready_to_read(fd) -> bool:
        return bool(select.select([fd], [], [], 0.01)[0])

    command_done = False
    while time.time() < min(end_time, end_time_no_output) and session.poll() is None:
        if ready_to_read(fd):
            try:
                data = os.read(fd, 4096)
            except BlockingIOError:
                logger.error("BlockingIOError while reading from subprocess.", exc_info=True)
                break
            if data:
                end_time_no_output = time.time() + no_output_timeout_duration
                buffer += data
                if terminal_pattern in buffer.decode("utf-8", errors="backslashreplace").replace("\r\n", "\n"):
                    command_done = True
                    break
        time.sleep(0.01)  # Prevents CPU hogging

    decoded = buffer.decode("utf-8", errors="backslashreplace").replace("\r\n", "\n")
    body = "\n".join(line for line in decoded.splitlines() if not line.startswith(terminal_pattern))

    if session.poll() is not None:
        msg = f"Subprocess exited unexpectedly.\nCurrent buffer: {decoded}"
        raise RuntimeError(msg, body)
    current_time = time.time()
    if not command_done and current_time >= min(end_time, end_time_no_output):
        if current_time >= end_time:
            msg = f"Timeout reached while reading from subprocess.\nCurrent buffer: {decoded}"
            raise TimeoutError(msg, body)
        else:
            msg = f"No output timeout reached while reading from subprocess.\nCurrent buffer: {decoded}"
            raise NoOutputTimeoutError(msg, body)

    return body


def get_background_pids(container_obj: Container):
    pids = container_obj.exec_run("ps -eo pid,comm --no-headers").output.decode().split("\n")
    pids = [x.split() for x in pids if x]
    pids = [x for x in pids if x[1] not in {"ps"} and x[0] != "1"]
    bash_pids = [x for x in pids if x[1] == "bash"]
    other_pids = [x for x in pids if x[1] not in {"bash"}]
    return bash_pids, other_pids


def terminate_docker_compose(docker_compose_path: Path, project_name: str | None = None) -> None:
    """
    Terminate a docker-compose project.
    
    Args:
        docker_compose_path: Path to the docker-compose.yml file
        project_name: Optional project name for the compose project (important for parallel execution)
    """
    terminate_cmd = [
        "docker",
        "compose",
        "-f",
        str(docker_compose_path),
    ]
    
    # Add project name if provided (important for parallel execution)
    if project_name:
        terminate_cmd.extend(["-p", project_name])
        logger.debug(f"Terminating docker-compose project: {project_name}")
    
    terminate_cmd.append("down")
    
    logger.debug("Terminating docker-compose with command: %s", shlex.join(terminate_cmd))
    compose = subprocess.Popen(
        terminate_cmd,
        stdin=PIPE,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        bufsize=1,  # line buffered
    )
    _, error = compose.communicate(timeout=DOCKER_COMPOSE_TERMINATION_DELAY)
    if error:
        logger.error(f"Unexpected compose termination error: {error}")


def terminate_docker_compose_with_project_name(docker_compose_path: Path, container_name_suffix: str | None = None) -> None:
    """
    Helper function to terminate docker-compose with proper project name handling for parallel execution.
    
    Args:
        docker_compose_path: Path to the docker-compose.yml file  
        container_name_suffix: Container suffix used to generate unique project name
    """
    project_name = None
    if container_name_suffix:
        challenge_name = docker_compose_path.parent.name
        project_name = f"{challenge_name}-{container_name_suffix}"
    
    terminate_docker_compose(docker_compose_path, project_name)


def cleanup_dynamic_network(network_name: str) -> None:
    """
    Clean up a specific dynamic CTF network with aggressive endpoint removal.
    
    Args:
        network_name: Name of the network to remove (e.g., 'ctfnet-abc123')
    """
    if not network_name or network_name == "ctfnet":
        # Don't remove the base ctfnet network
        return
    
    try:
        client = docker.from_env()
        network = client.networks.get(network_name)
        
        # First, try to disconnect all containers from this network
        try:
            network.reload()  # Get fresh network info
            connected_containers = network.attrs.get('Containers', {})
            
            if connected_containers:
                logger.debug(f"Network {network_name} has {len(connected_containers)} connected containers, disconnecting...")
                for container_id, endpoint_config in connected_containers.items():
                    try:
                        container = client.containers.get(container_id)
                        network.disconnect(container, force=True)
                        logger.debug(f"Forcefully disconnected container {container.name} from network {network_name}")
                    except docker.errors.NotFound:
                        logger.debug(f"Container {container_id} not found, likely already removed")
                    except Exception as e:
                        logger.debug(f"Failed to disconnect container {container_id}: {e}")
                        # Try to remove the container entirely if disconnect fails
                        try:
                            container = client.containers.get(container_id)
                            container.remove(force=True)
                            logger.debug(f"Forcefully removed problematic container {container.name}")
                        except Exception as remove_e:
                            logger.debug(f"Failed to remove container {container_id}: {remove_e}")
        except Exception as e:
            logger.debug(f"Failed to disconnect containers from network {network_name}: {e}")
        
        # Now try to remove the network
        network.remove()
        logger.debug(f"Successfully cleaned up dynamic network: {network_name}")
        
    except docker.errors.NotFound:
        logger.debug(f"Dynamic network {network_name} not found, likely already removed")
    except docker.errors.APIError as e:
        if "has active endpoints" in str(e):
            logger.warning(f"Network {network_name} has active containers, skipping")
        elif "not found" in str(e).lower():
            logger.debug(f"Network {network_name} already removed")
        else:
            logger.warning(f"Failed to remove network {network_name}: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error removing dynamic network {network_name}: {e}")


def cleanup_all_dynamic_networks() -> None:
    """
    Comprehensive cleanup of ALL dynamic CTF networks.
    This function finds and removes all networks matching the 'ctfnet-*' pattern,
    similar to the external cleanup script approach.
    """
    try:
        client = docker.from_env()
        networks = client.networks.list()
        
        # Find all dynamic ctfnet networks (those starting with 'ctfnet-')
        dynamic_networks = [net for net in networks if net.name.startswith('ctfnet-')]
        
        if dynamic_networks:
            logger.debug(f"Found {len(dynamic_networks)} dynamic CTF networks to clean up")
            for network in dynamic_networks:
                try:
                    # First try to remove directly
                    network.remove()
                    logger.debug(f"Cleaned up dynamic network: {network.name}")
                except docker.errors.APIError as e:
                    if "has active endpoints" in str(e):
                        # Network has active containers, try to disconnect them first
                        logger.debug(f"Network {network.name} has active endpoints, disconnecting containers...")
                        try:
                            # Reload network to get fresh endpoint info
                            network.reload()
                            # Disconnect all containers from this network
                            for container_id, endpoint_config in network.attrs.get('Containers', {}).items():
                                try:
                                    container = client.containers.get(container_id)
                                    network.disconnect(container, force=True)
                                    logger.debug(f"Disconnected container {container.name} from network {network.name}")
                                except Exception as disconnect_e:
                                    logger.debug(f"Failed to disconnect container {container_id}: {disconnect_e}")
                            
                            # Now try to remove the network again
                            network.remove()
                            logger.debug(f"Cleaned up dynamic network after disconnecting containers: {network.name}")
                        except Exception as cleanup_e:
                            logger.warning(f"Failed to forcefully clean up network {network.name}: {cleanup_e}")
                    else:
                        logger.warning(f"Failed to remove dynamic network {network.name}: {e}")
                except Exception as e:
                    logger.warning(f"Unexpected error removing dynamic network {network.name}: {e}")
        else:
            logger.debug("No dynamic CTF networks found to clean up")
    
    except docker.errors.DockerException as e:
        logger.warning(f"Docker error during network cleanup: {e}")
    except Exception as e:
        logger.warning(f"Unexpected error during comprehensive network cleanup: {e}")


def cleanup_dynamic_resources() -> None:
    """
    Comprehensive cleanup of dynamic CTF resources including networks and temporary files.
    This function provides thorough cleanup similar to the external cleanup script.
    """
    # Clean up all dynamic networks
    cleanup_all_dynamic_networks()
    
    # Clean up temporary docker-compose files
    try:
        import glob
        temp_files = glob.glob('/tmp/docker-compose-*')
        for temp_file in temp_files:
            try:
                Path(temp_file).unlink()
                logger.debug(f"Cleaned up temporary file: {temp_file}")
            except FileNotFoundError:
                pass  # File already removed
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {temp_file}: {e}")
        if temp_files:
            logger.debug(f"Cleaned up {len(temp_files)} temporary docker-compose files")
    except Exception as e:
        logger.warning(f"Error during temporary file cleanup: {e}")


def attach_network_interface_to_container(container_name: str, network_name: str = "ctfnet") -> None:
    """
    Attach a network interface to a container.
    
    Args:
        container_name: Name of the container to attach network to
        network_name: Name of the network to attach (defaults to 'ctfnet')
    """
    import time
    
    client = docker.from_env()
    
    # Retry logic for network attachment - increased for better reliability
    max_retries = 8  # Increased from 5 to 8 retries
    base_delay = 3  # Increased from 2 to 3 seconds
    
    for attempt in range(max_retries):
        try:
            # Get the network (docker-compose should have created it)
            try:
                network = client.networks.get(network_name)
                logger.debug(f"Found network {network_name}")
            except docker.errors.NotFound:
                if attempt < max_retries - 1:
                    wait_time = base_delay * (2 ** attempt)
                    logger.warning(f"Network {network_name} not found on attempt {attempt + 1}, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Network {network_name} not found after all retries")
                    raise RuntimeError(f"Network {network_name} not found after all retries")
            
            # Get the container object
            try:
                container = client.containers.get(container_name)
                logger.debug(f"Found container {container_name}")
            except docker.errors.NotFound:
                if attempt < max_retries - 1:
                    wait_time = base_delay * (2 ** attempt)
                    logger.warning(f"Container {container_name} not found on attempt {attempt + 1}, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Container {container_name} not found for network attachment")
                    raise RuntimeError(f"Container {container_name} not found")
            except Exception as e:
                logger.error(f"Error accessing container {container_name}: {e}")
                raise RuntimeError(f"Error accessing container {container_name}: {e}")
            
            # Check if already connected before attempting connection
            try:
                container.reload()
                network_settings = container.attrs.get('NetworkSettings', {})
                networks = network_settings.get('Networks', {})
                
                if network_name in networks:
                    network_info = networks[network_name]
                    ip_address = network_info.get('IPAddress')
                    if ip_address:
                        logger.info(f"Container {container_name} already connected to network {network_name} with IP {ip_address}")
                        return  # Already connected successfully
                    else:
                        logger.debug(f"Container appears connected to {network_name} but has no IP - will retry connection")
                        # Try to disconnect first to clean up partial connection
                        try:
                            network.disconnect(container, force=True)
                            time.sleep(2)  # Wait for cleanup
                        except:
                            pass
            except Exception as e:
                logger.debug(f"Failed to check existing connection: {e}")
            
            # Connect to the network
            try:
                network.connect(container)
                logger.info(f"Successfully connected container {container_name} to network {network_name}")
                
                # Wait for the connection to fully establish - increased wait time
                time.sleep(5)  # Increased from 3 to 5 seconds for better stability
                
                # Verify the connection more thoroughly
                network.reload()  # Refresh network info
                container.reload()  # Refresh container info
                
                # Check from network perspective
                connected_containers = network.attrs.get('Containers', {})
                network_connected = container.id in connected_containers
                
                # Check from container perspective
                network_settings = container.attrs.get('NetworkSettings', {})
                networks = network_settings.get('Networks', {})
                container_connected = network_name in networks
                
                # Check if we got an IP address
                ip_assigned = False
                if container_connected:
                    network_info = networks[network_name]
                    ip_address = network_info.get('IPAddress')
                    if ip_address:
                        ip_assigned = True
                        logger.debug(f"Container {container_name} assigned IP {ip_address} on network {network_name}")
                
                if network_connected and container_connected and ip_assigned:
                    logger.debug(f"Verified: Container {container_name} is properly connected to network {network_name}")
                    return  # Success!
                else:
                    if attempt < max_retries - 1:
                        logger.warning(f"Network connection verification failed on attempt {attempt + 1}")
                        logger.warning(f"  Network perspective: {network_connected}, Container perspective: {container_connected}, IP assigned: {ip_assigned}")
                        # Try to disconnect first in case of partial connection
                        try:
                            network.disconnect(container, force=True)
                            time.sleep(2)  # Wait for cleanup
                        except:
                            pass
                        continue
                    else:
                        logger.error(f"Network connection verification failed after all retries")
                        logger.error(f"  Network perspective: {network_connected}, Container perspective: {container_connected}, IP assigned: {ip_assigned}")
                        raise RuntimeError(f"Failed to verify network connection after {max_retries} attempts")
                        
            except docker.errors.APIError as e:
                if "already exists" in str(e).lower():
                    logger.debug(f"Container {container_name} already connected to network {network_name}")
                    return  # Success - already connected
                elif "endpoint with name" in str(e).lower() and "already exists" in str(e).lower():
                    logger.debug(f"Container {container_name} already connected to network {network_name} (endpoint exists)")
                    return  # Success - already connected
                else:
                    if attempt < max_retries - 1:
                        wait_time = base_delay * (2 ** attempt)
                        logger.warning(f"Failed to connect container on attempt {attempt + 1}: {e}, waiting {wait_time}s...")
                        time.sleep(wait_time)
                        continue
                    else:
                        logger.error(f"Failed to connect container {container_name} to network {network_name}: {e}")
                        raise RuntimeError(f"Failed to connect container to network: {e}")
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = base_delay * (2 ** attempt)
                    logger.warning(f"Unexpected error on attempt {attempt + 1}: {e}, waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    logger.error(f"Unexpected error connecting container {container_name} to network {network_name}: {e}")
                    raise RuntimeError(f"Unexpected network connection error: {e}")
        
        except RuntimeError:
            # Re-raise RuntimeError exceptions (these are our intentional errors)
            raise
        except Exception as e:
            if attempt < max_retries - 1:
                wait_time = base_delay * (2 ** attempt)
                logger.warning(f"Unexpected exception on attempt {attempt + 1}: {e}, waiting {wait_time}s...")
                time.sleep(wait_time)
                continue
            else:
                logger.error(f"Final attempt failed with exception: {e}")
                raise RuntimeError(f"Network attachment failed after {max_retries} attempts: {e}")
    
    # This should never be reached due to the return/raise statements above
    logger.error(f"Network attachment logic error - reached end of function without success or failure")
    raise RuntimeError("Network attachment logic error")


def get_docker_compose(
    docker_compose_path: Path, 
    container_name_suffix: str | None = None,
    dynamic_ports: bool = False,
    challenge_internal_port: int | None = None
) -> tuple[Path, dict[str, int], str | None]:
    """
    Start docker-compose services with optional dynamic port allocation.
    
    Args:
        docker_compose_path: Path to the docker-compose.yml file
        container_name_suffix: Optional suffix for container names to avoid conflicts
        dynamic_ports: If True, use dynamic port allocation to avoid conflicts
        challenge_internal_port: Optional internal port from challenge.json that should be exposed
        
    Returns:
        Tuple of (compose_path, port_mappings, project_name) where 
        port_mappings maps internal ports to external ports and 
        project_name is the actual normalized project name used by Docker Compose
    """
    actual_compose_path = docker_compose_path
    port_mappings = {}
    
    if dynamic_ports and container_name_suffix:
        # Generate unique network name for this instance
        dynamic_network_name = f"ctfnet-{container_name_suffix}"
        
        # Get available ports for the services
        import yaml
        try:
            with open(docker_compose_path) as f:
                compose_data = yaml.safe_load(f)
            
            # CRITICAL FIX FOR PARALLEL EXECUTION: Collect all unique port mappings first,
            # then allocate external ports atomically to prevent race conditions
            # Handle multiple services with same internal port by tracking service-specific mappings
            port_mappings_needed = []  # List of (service_name, original_external_port, internal_port)
            
            if "services" in compose_data:
                for service_name, service_config in compose_data["services"].items():
                    if "ports" in service_config:
                        for port_mapping in service_config["ports"]:
                            if isinstance(port_mapping, str) and ":" in port_mapping:
                                external_port, internal_port = port_mapping.split(":", 1)
                                port_mappings_needed.append((service_name, external_port, internal_port))
                                logger.debug(f"Found port mapping for {service_name}: {external_port}:{internal_port}")
                            elif isinstance(port_mapping, int):
                                # Handle integer port (just internal port specified)
                                internal_port = str(port_mapping)
                                port_mappings_needed.append((service_name, internal_port, internal_port))
                                logger.debug(f"Found port mapping for {service_name}: {port_mapping}")
            
            # Handle challenge internal port if specified
            if challenge_internal_port is not None:
                internal_port_str = str(challenge_internal_port)
                # Add for all services that don't already have this port mapped
                services_with_port = {service_name for service_name, _, internal_port in port_mappings_needed if internal_port == internal_port_str}
                if not services_with_port:
                    # Add a generic mapping for the challenge port
                    port_mappings_needed.append(("challenge", internal_port_str, internal_port_str))
                    logger.debug(f"Added challenge internal port: {internal_port_str}")
            
            # CRITICAL FIX: Atomically allocate all needed ports at once to prevent race conditions
            if port_mappings_needed:
                ports_count = len(port_mappings_needed)
                logger.debug(f"Need to allocate {ports_count} external ports for mappings: {[(s, e, i) for s, e, i in port_mappings_needed]}")
                
                try:
                    # Allocate all ports at once - this is atomic and race-condition free
                    external_ports = get_multiple_available_ports(ports_count)
                    logger.info(f"Allocated external ports: {external_ports}")
                    
                    # Map each service's internal port to its allocated external port
                    for i, (service_name, original_external_port, internal_port) in enumerate(port_mappings_needed):
                        # Use a unique key that includes the service name to avoid conflicts
                        mapping_key = f"{service_name}:{internal_port}"
                        port_mappings[mapping_key] = external_ports[i]
                        logger.debug(f"Mapped {service_name} internal port {internal_port} to external port {external_ports[i]}")
                        
                        # Also maintain backward compatibility with simple internal port key for single-service cases
                        if ports_count == 1:
                            port_mappings[internal_port] = external_ports[i]
                            
                except RuntimeError as e:
                    logger.warning(f"Could not allocate {ports_count} dynamic ports: {e}")
                    port_mappings = {}  # Reset mappings on failure
                        
        except Exception as e:
            logger.warning(f"Failed to parse compose file for dynamic ports: {e}")
            dynamic_ports = False
        
        if port_mappings:
            # Create modified docker-compose file
            try:
                actual_compose_path = create_dynamic_docker_compose(
                    docker_compose_path, 
                    container_name_suffix,
                    dynamic_network_name,
                    port_mappings
                )
                logger.info(f"Created dynamic docker-compose at {actual_compose_path} with port mappings: {port_mappings}")
            except Exception as e:
                logger.error(f"Failed to create dynamic docker-compose: {e}")
                actual_compose_path = docker_compose_path
                port_mappings = {}
    
    # CRITICAL FIX FOR PARALLEL EXECUTION: Generate unique project name
    # Docker Compose uses the directory name as project name by default, causing conflicts
    # when multiple instances run the same challenge. Use unique project name to isolate each instance.
    project_name = None
    if container_name_suffix:
        # Create unique project name using container suffix to avoid conflicts between parallel instances
        challenge_name = docker_compose_path.parent.name
        raw_project_name = f"{challenge_name}-{container_name_suffix}"
        
        # CRITICAL FIX: Normalize project name to match Docker Compose conventions
        # Docker Compose project names must:
        # - consist only of lowercase alphanumeric characters, hyphens, and underscores
        # - start with a letter or number
        import re
        
        # Convert to lowercase first
        normalized_project_name = raw_project_name.lower()
        
        # CRITICAL FIX: Replace ALL invalid characters including brackets, spaces, etc.
        # Docker allows: lowercase letters, numbers, hyphens, underscores ONLY
        # Replace any character that is NOT alphanumeric, hyphen, or underscore
        normalized_project_name = re.sub(r'[^a-z0-9_-]', '_', normalized_project_name)
        
        # Ensure it starts with a letter or number (not hyphen or underscore)
        if normalized_project_name and not normalized_project_name[0].isalnum():
            normalized_project_name = 'p' + normalized_project_name
        
        # Remove consecutive underscores/hyphens for cleaner names
        normalized_project_name = re.sub(r'[_-]+', '_', normalized_project_name)
        
        # Ensure project name isn't too long (Docker has limits)
        if len(normalized_project_name) > 50:
            # Truncate but keep the suffix for uniqueness
            # Keep the first 20 chars and last 20 chars to preserve both challenge name and uniqueness
            if len(normalized_project_name) > 40:
                normalized_project_name = normalized_project_name[:20] + '_' + normalized_project_name[-19:]
        
        # Final validation - ensure it's not empty and starts with alphanumeric
        if not normalized_project_name or not normalized_project_name[0].isalnum():
            normalized_project_name = f"project_{normalized_project_name}"
        
        # Additional safety: remove any remaining invalid characters that might have slipped through
        normalized_project_name = re.sub(r'[^a-z0-9_-]', '', normalized_project_name)
        
        # Ensure it's not empty after all the cleaning
        if not normalized_project_name:
            normalized_project_name = f"project_{int(time.time())}"
        
        project_name = normalized_project_name
        logger.debug(f"Normalized Docker Compose project name: {raw_project_name} -> {project_name}")
    else:
        # Fallback: use timestamp-based project name if no suffix provided
        import time
        raw_project_name = f"{docker_compose_path.parent.name}-{int(time.time())}"
        project_name = raw_project_name.lower()
        project_name = re.sub(r'[^a-z0-9_-]', '_', project_name)
        project_name = re.sub(r'[_-]+', '_', project_name)
        if not project_name[0].isalnum():
            project_name = 'p' + project_name
        logger.debug(f"Using fallback Docker Compose project name: {raw_project_name} -> {project_name}")
    
    logger.debug(f"Using Docker Compose project name: {project_name}")
    
    startup_cmd = [
        "docker",
        "compose",
        "-f",
        str(actual_compose_path),
        "-p",  # CRITICAL: Use explicit project name to prevent conflicts
        project_name,
        "up",
        "-d",
        "--force-recreate",
    ]
    logger.debug("Starting docker-compose with command: %s", shlex.join(startup_cmd))
    
    # CRITICAL FIX: Use subprocess cwd parameter instead of changing global working directory
    # This prevents race conditions in parallel execution where multiple threads change cwd
    challenge_dir = docker_compose_path.parent
    
    try:
        logger.debug(f"Running docker-compose from directory: {challenge_dir}")
        logger.info(f"🚀 Starting Docker Compose with project name: {project_name}")
        
        # Disable BuildKit to avoid compatibility issues with Docker Compose v2
        # This prevents the "0/1" build hanging issue
        compose_env = os.environ.copy()
        compose_env.update({
            'DOCKER_BUILDKIT': '1',
            'COMPOSE_DOCKER_CLI_BUILD': '0'
        })
        
        # Use subprocess cwd parameter to set working directory per-process
        # This is thread-safe unlike os.chdir()
        compose = subprocess.Popen(
            startup_cmd,
            stdin=PIPE,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            bufsize=1,  # line buffered
            cwd=str(challenge_dir),  # Set working directory per-process, not globally
            env=compose_env  # Use environment with BuildKit disabled
        )
        
        # CRITICAL FIX: Properly handle docker-compose output and check return code
        output, _ = compose.communicate(timeout=DOCKER_COMPOSE_STARTUP_DELAY)
        return_code = compose.returncode
        
        # Log docker-compose output for debugging
        if output and output.strip():
            logger.debug(f"Docker Compose output: {output.strip()}")
        
        # Check if docker-compose failed
        if return_code != 0:
            logger.error(f"❌ Docker Compose failed with return code: {return_code}")
            logger.error(f"Docker Compose output: {output}")
            raise RuntimeError(f"Docker Compose startup failed with return code {return_code}: {output}")
        else:
            logger.info(f"✅ Docker Compose started successfully with project name: {project_name}")
            
    except subprocess.TimeoutExpired:
        logger.error(f"❌ Docker Compose startup timed out after {DOCKER_COMPOSE_STARTUP_DELAY} seconds!")
        compose.kill()  # Kill the hanging process
        raise RuntimeError(f"Docker Compose startup timed out after {DOCKER_COMPOSE_STARTUP_DELAY} seconds")
    except Exception as e:
        logger.error(f"Failed to start docker-compose: {e}")
        raise e
    
    return actual_compose_path, port_mappings, project_name


def _get_container_mounts_list(container_mounts: list[str]) -> list[docker.types.Mount]:
    try:
        for i in range(len(container_mounts)):
            path = Path(container_mounts[i]).absolute()
            if path.is_dir():
                container_mounts[i] = docker.types.Mount(source=str(path), target=f"/{path.name}")
        return container_mounts
    except Exception:
        logger.warning("Failed to process container mounts, skipping mount.")
        return []


def _get_non_persistent_container(
    ctr_name: str, image_name: str, container_mounts: list[str], enable_network_restrictions: bool = True
) -> tuple[subprocess.Popen, set[str]]:
    container_mounts_list = _get_container_mounts_list(container_mounts)
    client = docker.from_env()
    
    # Container configuration - need privileged mode for iptables network restrictions
    container_kwargs = {
        "image": image_name,
        "command": "/bin/bash -l -m",
        "name": ctr_name,
        "stdin_open": True,
        "tty": True,
        "detach": True,
        "auto_remove": True,
        "mounts": container_mounts_list,
    }
    
    # Add privileged mode if network restrictions are enabled (required for iptables)
    if enable_network_restrictions:
        container_kwargs["privileged"] = True
    
    # CRITICAL: Add resource limits to prevent container crashes due to resource exhaustion
    # These limits help prevent the Docker daemon from killing containers during parallel execution
    resource_limits = {
        # Memory limits - allow enough for package installation but prevent runaway processes
        "mem_limit": "2g",  # 2GB memory limit
        "memswap_limit": "3g",  # 3GB total memory+swap limit
        # CPU limits - prevent CPU starvation in parallel execution
        "cpu_period": 100000,  # 100ms period
        "cpu_quota": 150000,   # 150ms quota = 1.5 CPU cores max
        # Prevent excessive file descriptor usage
        "ulimits": [
            docker.types.Ulimit(name='nofile', soft=1024, hard=2048),  # File descriptors
            docker.types.Ulimit(name='nproc', soft=512, hard=1024),    # Process count
        ],
        # Set process limits to prevent fork bombs
        "pids_limit": 1000,
    }
    
    # Apply resource limits for non-privileged containers or when running in parallel
    # For privileged containers, be more conservative to prevent system issues
    if enable_network_restrictions or "parallel" in ctr_name:
        # More conservative limits for privileged/parallel containers
        resource_limits.update({
            "mem_limit": "1.5g",
            "memswap_limit": "2g", 
            "cpu_quota": 100000,  # 1.0 CPU core max for parallel execution
            "pids_limit": 500,
        })
        logger.debug(f"Applying conservative resource limits for container {ctr_name}")
    
    container_kwargs.update(resource_limits)
    
    logger.debug("Starting container with image: %s, name: %s", image_name, ctr_name)
    logger.debug("Resource limits: mem=%s, cpu_quota=%s, pids=%s", 
                 resource_limits.get("mem_limit"), 
                 resource_limits.get("cpu_quota"), 
                 resource_limits.get("pids_limit"))
    
    try:
        container_obj = client.containers.run(**container_kwargs)
    except docker.errors.APIError as e:
        if "resource" in str(e).lower() or "limit" in str(e).lower():
            logger.warning(f"Container creation failed due to resource constraints: {e}")
            logger.warning("Retrying with reduced resource limits...")
            # Fallback with minimal resource limits
            fallback_limits = {
                "mem_limit": "1g",
                "memswap_limit": "1.5g",
                "cpu_quota": 50000,  # 0.5 CPU core
                "pids_limit": 250,
            }
            container_kwargs.update(fallback_limits)
            try:
                container_obj = client.containers.run(**container_kwargs)
                logger.info(f"Container {ctr_name} created with fallback resource limits")
            except Exception as fallback_e:
                logger.error(f"Failed to create container even with minimal resources: {fallback_e}")
                raise RuntimeError(f"Container creation failed: {fallback_e}") from fallback_e
        else:
            logger.error(f"Container creation failed: {e}")
            raise RuntimeError(f"Container creation failed: {e}") from e
    except Exception as e:
        logger.error(f"Unexpected error creating container: {e}")
        raise RuntimeError(f"Container creation failed: {e}") from e
    
    # Wait a moment for container to fully initialize
    time.sleep(2)
    
    # Validate container is running before proceeding
    try:
        container_obj.reload()
        if container_obj.status != "running":
            logger.error(f"Container {ctr_name} failed to start properly, status: {container_obj.status}")
            # Try to get container logs for debugging
            try:
                logs = container_obj.logs(tail=50).decode('utf-8', errors='ignore')
                logger.error(f"Container logs: {logs}")
            except:
                pass
            raise RuntimeError(f"Container failed to start, status: {container_obj.status}")
    except docker.errors.NotFound:
        logger.error(f"Container {ctr_name} disappeared immediately after creation")
        raise RuntimeError("Container disappeared after creation")
    except Exception as e:
        logger.error(f"Failed to validate container status: {e}")
        raise RuntimeError(f"Container validation failed: {e}") from e
    
    startup_cmd = [
        "docker",
        "exec",
        "-i",
        ctr_name,
        "/bin/bash",
        "-l",
    ]
    logger.debug("Starting container with command: %s", shlex.join(startup_cmd))
    
    try:
        container = subprocess.Popen(
            startup_cmd,
            stdin=PIPE,
            stdout=PIPE,
            stderr=STDOUT,
            text=True,
            bufsize=1,  # line buffered
        )
    except Exception as e:
        logger.error(f"Failed to create subprocess for container communication: {e}")
        # Clean up the container if subprocess creation failed
        try:
            container_obj.remove(force=True)
        except:
            pass
        raise RuntimeError(f"Subprocess creation failed: {e}") from e
    
    time.sleep(DOCKER_START_UP_DELAY)
    
    # try to read output from container setup (usually an error), timeout if no output
    try:
        output = read_with_timeout(container, lambda: list(), timeout_duration=2)
        if output:
            logger.error(f"Unexpected container setup output: {output}")
            # Check if this indicates a serious problem
            if any(keyword in output.lower() for keyword in ["error", "failed", "cannot", "permission denied"]):
                logger.error(f"Container setup failed with errors: {output}")
                # Don't fail immediately, but log the issue
                logger.warning("Container may be unstable due to setup errors")
    except Exception as e:
        logger.warning(f"Failed to read container setup output: {e}")
        # This is not necessarily fatal, continue
    
    # Final health check
    try:
        # Test basic container communication
        test_result = container_obj.exec_run("echo 'container_ready'")
        if test_result.exit_code != 0 or b"container_ready" not in test_result.output:
            logger.warning(f"Container {ctr_name} failed basic health check")
            logger.warning(f"Health check result: exit_code={test_result.exit_code}, output={test_result.output}")
        else:
            logger.debug(f"Container {ctr_name} passed health check")
    except Exception as e:
        logger.warning(f"Container health check failed: {e}")
        # Don't fail completely, but this is concerning
    
    # NOTE: Network restrictions are now applied AFTER environment setup in SWEEnv.reset()
    # This allows package installation during setup while still protecting against external access during agent execution
    
    # bash PID is always 1 for non-persistent containers
    return container, {
        "1",
    }


def _get_persistent_container(
    ctr_name: str, image_name: str, container_mounts: list[str], enable_network_restrictions: bool = True
) -> tuple[subprocess.Popen, set[str]]:
    client = docker.from_env()
    containers = client.containers.list(all=True, filters={"name": ctr_name})
    container_created = False
    
    if ctr_name in [c.name for c in containers]:
        container_obj = client.containers.get(ctr_name)
        if container_obj.status in {"created"}:
            container_obj.start()
        elif container_obj.status in {"running"}:
            pass
        elif container_obj.status in {"exited"}:
            container_obj.restart()
        elif container_obj.status in {"paused"}:
            container_obj.unpause()
        else:
            msg = f"Unexpected container status: {container_obj.status}"
            raise RuntimeError(msg)
    else:
        container_mounts_list = _get_container_mounts_list(container_mounts)
        # Container configuration - need privileged mode for iptables network restrictions
        container_kwargs = {
            "image": image_name,
            "command": "/bin/bash -l -m",
            "name": ctr_name,
            "stdin_open": True,
            "tty": True,
            "detach": True,
            "auto_remove": not True,  # persistent containers shouldn't auto-remove
            "mounts": container_mounts_list,
        }
        # Add privileged mode if network restrictions are enabled (required for iptables)
        if enable_network_restrictions:
            container_kwargs["privileged"] = True
        
        container_obj = client.containers.run(**container_kwargs)
        container_obj.start()
        container_created = True
        
    startup_cmd = [
        "docker",
        "exec",
        "-i",
        ctr_name,
        "/bin/bash",
        "-l",
    ]
    logger.debug("Starting container with command: %s", shlex.join(startup_cmd))
    container = subprocess.Popen(
        startup_cmd,
        stdin=PIPE,
        stdout=PIPE,
        stderr=STDOUT,
        text=True,
        bufsize=1,  # line buffered
    )
    time.sleep(DOCKER_START_UP_DELAY)
    # try to read output from container setup (usually an error), timeout if no output
    output = read_with_timeout(container, lambda: list(), timeout_duration=2)
    if output:
        logger.error(f"Unexpected container setup output: {output}")
    
    # NOTE: Network restrictions are now applied AFTER environment setup in SWEEnv.reset()
    # For existing containers, restrictions should already be in place from previous setup
    # For new containers, restrictions will be applied after setup is complete
    
    # Get the process IDs of the container
    # There should be at least a head process and possibly one child bash process
    bash_pids, other_pids = get_background_pids(container_obj)
    total_time_slept = DOCKER_START_UP_DELAY
    # Let's wait for a maximum of 5 x DOCKER_START_UP_DELAY seconds
    # and then check again.
    while len(bash_pids) > 1 or len(other_pids) > 0:
        time.sleep(1)
        total_time_slept += 1
        bash_pids, other_pids = get_background_pids(container_obj)
        if total_time_slept > 5 * DOCKER_START_UP_DELAY:
            break
    bash_pid = 1
    if len(bash_pids) == 1:
        bash_pid = bash_pids[0][0]
    elif len(bash_pids) > 1 or len(other_pids) > 0:
        # Enhanced alien process handling with recovery attempts
        logger.warning(f"Detected potential alien processes. Bash PIDs: {bash_pids}, Other PIDs: {other_pids}")
        
        # Try to recover by cleaning up stuck processes
        recovery_successful = False
        
        # Attempt 1: Try to kill stuck processes gracefully
        logger.info("🔧 Attempting to clean up stuck processes...")
        try:
            all_stuck_pids = [pid for pid, _ in bash_pids[1:]] + [pid for pid, _ in other_pids]  # Skip first bash PID
            
            if all_stuck_pids:
                logger.debug(f"Attempting to kill stuck processes: {all_stuck_pids}")
                
                # First try SIGTERM
                for pid in all_stuck_pids:
                    try:
                        result = container_obj.exec_run(f"kill -TERM {pid}")
                        logger.debug(f"SIGTERM to PID {pid}: exit_code={result.exit_code}")
                    except Exception as e:
                        logger.debug(f"SIGTERM failed for PID {pid}: {e}")
                
                time.sleep(3)  # Wait for graceful termination
                
                # Check if processes are gone
                bash_pids_after_term, other_pids_after_term = get_background_pids(container_obj)
                if len(bash_pids_after_term) <= 1 and len(other_pids_after_term) == 0:
                    logger.info("✅ Graceful cleanup successful")
                    recovery_successful = True
                    bash_pid = bash_pids_after_term[0][0] if bash_pids_after_term else 1
                else:
                    # Try SIGKILL
                    logger.debug("Graceful cleanup failed, trying SIGKILL...")
                    remaining_pids = [pid for pid, _ in bash_pids_after_term[1:]] + [pid for pid, _ in other_pids_after_term]
                    
                    for pid in remaining_pids:
                        try:
                            result = container_obj.exec_run(f"kill -9 {pid}")
                            logger.debug(f"SIGKILL to PID {pid}: exit_code={result.exit_code}")
                        except Exception as e:
                            logger.debug(f"SIGKILL failed for PID {pid}: {e}")
                    
                    time.sleep(3)  # Wait for forceful termination
                    
                    # Final check
                    bash_pids_final, other_pids_final = get_background_pids(container_obj)
                    if len(bash_pids_final) <= 1 and len(other_pids_final) == 0:
                        logger.info("✅ Forceful cleanup successful")
                        recovery_successful = True
                        bash_pid = bash_pids_final[0][0] if bash_pids_final else 1
                    else:
                        logger.warning(f"Forceful cleanup partially failed. Remaining: bash={bash_pids_final}, other={other_pids_final}")
        
        except Exception as e:
            logger.warning(f"Exception during stuck process cleanup: {e}")
        
        # Attempt 2: Check if remaining processes are uninterruptible
        if not recovery_successful:
            logger.info("🔍 Analyzing remaining processes for uninterruptible states...")
            bash_pids_current, other_pids_current = get_background_pids(container_obj)
            uninterruptible_processes = []
            killable_processes = []
            
            all_current_pids = bash_pids_current + other_pids_current
            for pid, comm in all_current_pids:
                if pid == "1":  # Skip init process
                    continue
                    
                try:
                    # Check process state
                    stat_result = container_obj.exec_run(f"cat /proc/{pid}/stat 2>/dev/null")
                    if stat_result.exit_code == 0:
                        stat_fields = stat_result.output.decode().strip().split()
                        if len(stat_fields) > 2:
                            process_state = stat_fields[2]
                            if process_state == 'D':  # Uninterruptible sleep
                                uninterruptible_processes.append((pid, comm, process_state))
                                logger.warning(f"Process {pid} ({comm}) is in uninterruptible sleep - cannot be killed")
                            elif process_state in ['S', 'R', 'T', 'Z']:  # Interruptible states
                                killable_processes.append((pid, comm, process_state))
                            else:
                                logger.debug(f"Process {pid} ({comm}) in state {process_state}")
                except Exception as e:
                    logger.debug(f"Failed to check state for PID {pid}: {e}")
                    # Assume it's killable if we can't check
                    killable_processes.append((pid, comm, "unknown"))
            
            # If most processes are uninterruptible, we'll be more lenient
            total_alien_processes = len(all_current_pids) - (1 if any(pid == "1" for pid, _ in all_current_pids) else 0)
            uninterruptible_count = len(uninterruptible_processes)
            
            if uninterruptible_count > 0:
                logger.warning(f"Found {uninterruptible_count}/{total_alien_processes} uninterruptible processes")
                
                # If majority are uninterruptible, this is likely due to filesystem operations (like grep)
                # In this case, we'll be more lenient and allow the container to be used
                if uninterruptible_count >= total_alien_processes * 0.5:  # 50% or more are uninterruptible
                    logger.warning("⚠️  Majority of processes are uninterruptible (likely due to I/O operations)")
                    logger.warning("🔄 Allowing container reuse with understanding that these processes may eventually exit")
                    recovery_successful = True
                    
                    # Use the first bash PID if available, otherwise use 1
                    if len(bash_pids_current) > 0:
                        bash_pid = bash_pids_current[0][0]
                    else:
                        bash_pid = 1
                        
                    # Log the uninterruptible processes for monitoring
                    for pid, comm, state in uninterruptible_processes:
                        logger.warning(f"  Uninterruptible process: PID {pid} ({comm}) in state {state}")
        
        # Attempt 3: Container restart as last resort
        if not recovery_successful and not container_created:
            logger.warning("🔄 Attempting container restart to clear stuck processes...")
            try:
                container_obj.restart(timeout=30)
                time.sleep(DOCKER_START_UP_DELAY)
                
                # Check processes after restart
                bash_pids_restart, other_pids_restart = get_background_pids(container_obj)
                if len(bash_pids_restart) <= 1 and len(other_pids_restart) == 0:
                    logger.info("✅ Container restart successful - processes cleared")
                    recovery_successful = True
                    bash_pid = bash_pids_restart[0][0] if bash_pids_restart else 1
                else:
                    logger.warning(f"Container restart didn't fully clear processes: bash={bash_pids_restart}, other={other_pids_restart}")
            except Exception as e:
                logger.error(f"Container restart failed: {e}")
        
        # If all recovery attempts failed, raise the original error but with more context
        if not recovery_successful:
            final_bash_pids, final_other_pids = get_background_pids(container_obj)
            
            # Provide detailed information about what processes are stuck
            process_details = []
            for pid, comm in final_bash_pids + final_other_pids:
                try:
                    # Get more detailed process information
                    cmdline_result = container_obj.exec_run(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
                    stat_result = container_obj.exec_run(f"cat /proc/{pid}/stat 2>/dev/null")
                    
                    cmdline = cmdline_result.output.decode().strip() if cmdline_result.exit_code == 0 else "unknown"
                    state = "unknown"
                    if stat_result.exit_code == 0:
                        stat_fields = stat_result.output.decode().strip().split()
                        if len(stat_fields) > 2:
                            state = stat_fields[2]
                    
                    process_details.append(f"PID {pid} ({comm}): {cmdline} [state: {state}]")
                except Exception:
                    process_details.append(f"PID {pid} ({comm}): [details unavailable]")
            
            msg = (
                "Detected alien processes attached or running. Please ensure that no other agents "
                f"are running on this container.\n"
                f"Bash PIDs: {final_bash_pids}\n"
                f"Other PIDs: {final_other_pids}\n"
                f"Process details:\n" + "\n".join(f"  {detail}" for detail in process_details) + "\n"
                f"Recovery attempts failed. This may be due to uninterruptible processes from "
                f"expensive operations like filesystem searches (grep -r, find, etc.). "
                f"Consider using a new container or waiting for I/O operations to complete."
            )
            raise RuntimeError(msg)
    
    return container, {str(bash_pid), "1"}


def get_container(
    ctr_name: str, image_name: str, container_mounts: list[str], persistent: bool = False, enable_network_restrictions: bool = True
) -> tuple[subprocess.Popen, set]:
    """
    Get a container object for a given container name and image name

    Arguments:
        ctr_name (str): Name of container
        image_name (str): Name of image
        container_mounts (list[str]): List of paths to mount in container
        persistent (bool): Whether to use a persistent container or not
        enable_network_restrictions (bool): Whether to enable network restrictions in the container
    Returns:
        Container object and parent PIDs
    """
    if not image_exists(image_name):
        msg = (
            f"Image {image_name} not found. Please ensure it is built and available. "
            "Please double-check that you followed all installation/setup instructions from the "
            "readme."
        )
        raise RuntimeError(msg)

    if persistent:
        return _get_persistent_container(ctr_name, image_name, container_mounts=container_mounts, enable_network_restrictions=enable_network_restrictions)
    else:
        return _get_non_persistent_container(ctr_name, image_name, container_mounts=container_mounts, enable_network_restrictions=enable_network_restrictions)


def image_exists(image_name: str) -> bool:
    """
    Check that the image exists and give some better error messages.

    Arguments:
        image_name: Name of image
    Returns:
        bool: True if image exists
    """
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        docker_not_running = any(
            (
                "connection aborted" in str(e).lower(),
                "connection refused" in str(e).lower(),
                "error while fetching server api version" in str(e).lower(),
            ),
        )
        if docker_not_running:
            msg = (
                "Probably the Docker daemon is not running. Please start the Docker daemon and try again. "
                "If Docker issues persist, please check out https://princeton-nlp.github.io/SWE-agent/installation/tips/"
            )
            raise RuntimeError(msg) from e
        raise
    filterred_images = client.images.list(filters={"reference": image_name})
    if len(filterred_images) == 0:
        return False
    elif len(filterred_images) > 1:
        RuntimeError(f"Multiple images found for {image_name}, that's weird.")
    attrs = filterred_images[0].attrs
    if attrs is not None:
        logger.info(
            f"Found image {image_name} with tags: {attrs['RepoTags']}, created: {attrs['Created']} "
            f"for {attrs['Os']} {attrs['Architecture']}.",
        )
    return True


def get_commit(api: GhApi, owner: str, repo: str, ref: str | None = None):
    """Get commit object from github api

    Args:
        api (GhApi):
        owner (str): Repo owner, e.g., "princeton-nlp"
        repo (str): Repo, e.g., "SWE-agent"
        ref (str, optional): Branch, tag or commit hash

    Returns:
        _type_: _description_
    """
    if ref:
        return api.repos.get_commit(owner, repo, ref)
    return api.repos.list_commits(owner, repo)[0]


class InvalidGithubURL(ValueError): ...


def parse_gh_issue_url(issue_url: str) -> tuple[str, str, str]:
    """
    Returns:
        owner: Repo owner
        repo: Repo name
        issue number: Issue number as str

    Raises:
        InvalidGithubURL: If the URL is not a valid github issue URL
    """
    match = GITHUB_ISSUE_URL_PATTERN.search(issue_url)
    if not match:
        msg = f"Invalid GitHub issue URL: {issue_url}"
        raise InvalidGithubURL(msg)
    res = match.groups()
    assert len(res) == 3
    return tuple(res)  # type: ignore


def parse_gh_repo_url(repo_url: str) -> tuple[str, str]:
    """
    Returns:
        owner: Repo owner/org
        repo: Repo name

    Raises:
        InvalidGithubURL: If the URL is not a valid github repo URL
    """
    match = GITHUB_REPO_URL_PATTERN.search(repo_url)
    if not match:
        msg = f"Invalid GitHub issue URL: {repo_url}"
        raise InvalidGithubURL(msg)
    res = match.groups()
    assert len(res) == 2
    return tuple(res)  # type: ignore


def get_gh_issue_data(issue_url: str, *, token: str = ""):
    """Returns github issue data in the form of a dictionary.
    See https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#get-an-issue
    for return format
    """
    owner, repo, issue_number = parse_gh_issue_url(issue_url)
    api = GhApi(token=token)
    return api.issues.get(owner, repo, issue_number)


def get_problem_statement_from_github_issue(owner: str, repo: str, issue_number: str, *, token: str | None = "") -> str:
    """Return problem statement from github issue"""
    api = GhApi(token=token)
    issue = api.issues.get(owner, repo, issue_number)
    title = issue.title if issue.title else ""
    body = issue.body if issue.body else ""
    return f"{title}\n{body}\n"


class InstanceBuilder:
    def __init__(self, token: str | None = None, allow_dirty_repo: bool = False):
        """This helper class is used to build the data for an instance object,
        retrieving problem statements from github issues or local files and setting
        repo paths from github urls or local paths.
        """
        # Args that will be passed to the Instance constructor
        self.args: dict[str, Any] = {}
        self._github_token = token
        self._allow_dirty_repo = allow_dirty_repo
        self._instance_id_problem_suffix = ""

    def set_problem_statement_from_gh_issue(self, issue_url: str):
        owner, repo, issue_number = parse_gh_issue_url(issue_url)
        self.args["problem_statement"] = get_problem_statement_from_github_issue(
            owner,
            repo,
            issue_number,
            token=self._github_token,
        )
        self.args["instance_id"] = f"{owner}__{repo}-i{issue_number}"
        self.args["problem_statement_source"] = "online"

    def set_server_description(self, server_name: str | None, port: int | None, external_port: int | None = None) -> None:
        """For CTF challenges
        
        Args:
            server_name: The server hostname/alias 
            port: The internal port the service runs on
            external_port: The external port mapped to the internal port (for dynamic port mapping)
        """
        if server_name is None or port is None:
            self.args["challenge"]["server_description"] = ""
            return
        
        # IMPORTANT: For container-to-container communication, ALWAYS use internal port and service name
        # External ports are only for host-to-container communication
        # Since the agent runs inside a container, it should use the service name and internal port
        
        if self.args["challenge"]["category"] in {"web", "misc"} and self.args["challenge"].get("proto") != "nc":
            self.args["challenge"]["server_description"] = (
                f"The challenge web server is running on `{server_name}` port `{port}` and you can access it from within the container environment using `curl http://{server_name}:{port}`."
            )
        else:
            self.args["challenge"]["server_description"] = (
                f"The challenge server is running on `{server_name}` port `{port}` and you can access it from within the container environment using `connect_start {server_name} {port}`."
            )

    def set_problem_statement_from_challenge_json(self, file_path: str) -> None:
        """For CTF challenges"""
        challenge = json.loads(Path(file_path).read_text())
        self.args["challenge"] = challenge
        self.args["challenge"]["files"] = challenge.get("files", [])
        self.args["challenge"]["points"] = challenge.get("points", 10)
        self.args["challenge"]["category_friendly"] = CTF_CHALLENGES_CATEGORIES.get(challenge["category"])
        if (Path(file_path).parent / "docker-compose.yml").is_file():
            logger.debug(f"Found docker_compose file in {Path(file_path).parent}")
            self.args["challenge"]["docker_compose"] = Path(file_path).parent / "docker-compose.yml"
        self.args["challenge"]["port"] = challenge.get("internal_port") or challenge.get("port")
        if "box" in challenge:
            self.args["challenge"]["server_name"] = challenge["box"] or "127.0.0.1"
        else:
            self.args["challenge"]["server_name"] = ""
        self.args["challenge"]["file_path"] = file_path
        self.set_server_description(self.args["challenge"]["server_name"], self.args["challenge"]["port"])
        self.set_problem_statement_from_text(f"{challenge['name']} {challenge['description']}")
        self.args["instance_id"] = (
            # sanitize 'name' to only alphanumeric characters
            challenge.get("category", "misc") + "_" + "".join(a for a in self.args["challenge"]["name"] if a.isalnum())
        )

    def set_problem_statement_from_file(self, file_path: str):
        if Path(file_path).name == "challenge.json":
            self.set_problem_statement_from_challenge_json(file_path)
        else:
            self.set_problem_statement_from_text(Path(file_path).read_text())

    def set_problem_statement_from_text(self, text: str):
        self.args["problem_statement"] = text
        self.args["instance_id"] = hashlib.sha256(self.args["problem_statement"].encode()).hexdigest()[:6]
        self.args["problem_statement_source"] = "local"

    def set_problem_statement(self, data_path: str):
        """Get problem statement for a single instance from a github issue url or a
        path to a markdown or text file.
        """
        if data_path.startswith("text://"):
            return self.set_problem_statement_from_text(data_path.removeprefix("text://"))
        if is_github_issue_url(data_path):
            return self.set_problem_statement_from_gh_issue(data_path)
        if Path(data_path).is_file():
            return self.set_problem_statement_from_file(data_path)
        msg = f"Not sure how to get problem statement from {data_path=}."
        raise ValueError(msg)

    def set_repo_info_from_gh_url(self, url: str, base_commit: str | None = None):
        owner, repo = parse_gh_repo_url(url)
        self.args["repo"] = f"{owner}/{repo}"
        self.args["repo_type"] = "github"
        # Always get commit hash, because base_commit can also be branch or tag
        api = GhApi(token=self._github_token)
        self.args["base_commit"] = get_commit(api, owner, repo, ref=base_commit).sha
        if base_commit != self.args["base_commit"]:
            logger.info(f"Base commit reference {base_commit} resolved to commit hash {self.args['base_commit']}")
        self.args["version"] = self.args["base_commit"][:7]

    def set_repo_info_from_local_path(self, path: str, base_commit: str | None = None):
        self.args["repo"] = str(Path(path).resolve())
        self.args["repo_type"] = "local"
        if base_commit:
            self.args["base_commit"] = base_commit
        else:
            try:
                repo = Repo(path)
            except InvalidGitRepositoryError as e:
                if self._allow_dirty_repo:
                    # When allow_dirty_repo is True, provide a fallback for non-git directories
                    import hashlib
                    fallback_commit = hashlib.sha256(str(Path(path).resolve()).encode()).hexdigest()[:40]
                    self.args["base_commit"] = fallback_commit
                    self.args["version"] = self.args["base_commit"][:7]
                    return
                else:
                    msg = f"Could not find git repository at {path=}."
                    raise ValueError(msg) from e
            if not self._allow_dirty_repo and repo.is_dirty() and "PYTEST_CURRENT_TEST" not in os.environ:
                msg = f"Local git repository {path} is dirty. Please commit or stash changes."
                raise ValueError(msg)
            self.args["base_commit"] = repo.head.object.hexsha
        self.args["version"] = self.args["base_commit"][:7]

    def set_repo_info(self, repo: str, base_commit: str | None = None):
        if is_github_repo_url(repo):
            self.set_repo_info_from_gh_url(repo, base_commit=base_commit)
        elif Path(repo).is_dir():
            self.set_repo_info_from_local_path(repo, base_commit=base_commit)
        else:
            msg = f"Could not determine repo path from {repo=}."
            raise ValueError(msg)

    def set_from_dict(self, instance_dict: dict[str, Any]):
        self.args |= instance_dict

    def set_missing_fields(self):
        # TODO: This field is only needed while swe_env is using some questionable logic
        # to determine whether to clone from a mirror or not. This should be removed in the future.
        # Values: 'swe-bench' (loaded from json/jsonl for swe-bench style inference),
        # 'online' (loaded from github issue or similar) or 'local' (loaded from local file)
        if "problem_statement_source" not in self.args:
            self.args["problem_statement_source"] = "swe-bench"
        if "repo_type" not in self.args:
            self.args["repo_type"] = "github"

    def validate(self):
        required_fields = [
            "problem_statement",
            "instance_id",
            "repo",
            "repo_type",
            "base_commit",
            "version",
            "problem_statement_source",
        ]
        if not all(x in self.args for x in required_fields):
            missing = set(required_fields) - set(self.args.keys())
            msg = f"Missing required fields: {missing=}"
            raise ValueError(msg)
        if self.args["repo_type"] not in {"github", "local"}:
            msg = f"Invalid repo type: {self.args['repo_type']=}"
            raise ValueError(msg)
        if self.args["repo_type"] == "github" and self.args["repo"].count("/") != 1:
            msg = f"Invalid repo format for {self.args['repo_type']=}: {self.args['repo']=}"
            raise ValueError(msg)

    def build(self) -> dict[str, Any]:
        self.set_missing_fields()
        self.validate()
        return self.args

    def update_server_description_with_port_mapping(self, port_mappings: dict[str, int]) -> None:
        """Update server description after dynamic port mapping is established
        
        Args:
            port_mappings: Dictionary mapping internal ports (as strings) to external ports
        """
        if "challenge" not in self.args:
            return
            
        challenge = self.args["challenge"]
        internal_port = challenge.get("port")
        server_name = challenge.get("server_name")
        
        if internal_port is not None and str(internal_port) in port_mappings:
            external_port = port_mappings[str(internal_port)]
            # Update the server description with the external port
            self.set_server_description(server_name, internal_port, external_port)
            # Store the port mapping info for reference
            challenge["external_port"] = external_port
            challenge["port_mapping"] = port_mappings


def get_instances(
    file_path: str,
    base_commit: str | None = None,
    split: str | None = None,
    token: str | None = None,
    *,
    repo_path: str = "",
    allow_dirty_repo: bool = False,
) -> list[dict[str, Any]]:
    """
    Getter function for handling json, jsonl files

    Args:
        file_path (str): Path to file

    Returns:
        List of instances as dictionaries
    """

    def instance_from_dict(instances):
        ib = InstanceBuilder(token=token, allow_dirty_repo=allow_dirty_repo)
        ib.set_from_dict(instances)
        return ib.build()

    def postproc_instance_list(instances):
        if isinstance(instances, dict):
            msg = "Expected a list of instances, got a dictionary."
            raise ValueError(msg)
        return [instance_from_dict(x) for x in instances]

    # The next if statement is very brittle logic to determine if we're processing a single instance
    if (
        file_path.startswith("text://")
        or (
            Path(file_path).is_file()
            and (Path(file_path).suffix in [".md", ".txt"] or Path(file_path).name == "challenge.json")
        )
        or is_github_issue_url(file_path)
    ):
        ib = InstanceBuilder(token=token, allow_dirty_repo=allow_dirty_repo)
        ib.set_problem_statement(file_path)
        if repo_path:
            ib.set_repo_info(repo_path, base_commit=base_commit)
        elif is_github_repo_url(file_path):
            ib.set_repo_info_from_gh_url(file_path, base_commit=base_commit)
        else:
            msg = f"Could not determine repo path from {file_path=}, {repo_path=}"
            raise ValueError(msg)

        return [ib.build()]

    if base_commit:
        msg = "base_commit must be empty if running over multiple problem statements"
        raise ValueError(msg)

    if repo_path:
        if not Path(repo_path).exists():
            msg = f"Specified repository path {repo_path} does not exist"
            raise FileNotFoundError(msg)
        msg = "repo_path must be empty if running over multiple problem statements"
        raise ValueError(msg)

    # If file_path is a directory, attempt load from disk
    if Path(file_path).is_dir():
        try:
            dataset_or_dict = load_from_disk(file_path)
            if isinstance(dataset_or_dict, dict):
                return postproc_instance_list(dataset_or_dict[split])
            return postproc_instance_list(dataset_or_dict)
        except FileNotFoundError:
            # Raised by load_from_disk if the directory is not a dataset directory
            pass

    if base_commit is not None:
        msg = "base_commit must be None if data_path is not a github issue url"
        raise ValueError(msg)

    # If file_path is a file, load the file
    if file_path.endswith(".json"):
        with open(file_path) as file:
            return postproc_instance_list(json.load(file))
    if file_path.endswith(".jsonl"):
        return postproc_instance_list([json.loads(x) for x in Path(file_path).read_text().splitlines(keepends=True)])

    # Attempt load from HF datasets as a last resort
    try:
        return postproc_instance_list(load_dataset(file_path, split=split))
    except Exception as e:
        msg = (
            f"Could not load instances from {file_path}. "
            "Please ensure --data_path is a GitHub URL, a SWE-bench HuggingFace dataset, or a JSON/JSONL file."
        )
        raise ValueError(msg) from e


def get_associated_commit_urls(org: str, repo: str, issue_number: str, *, token: str = "") -> list[str]:
    """Return the URLs of commits that would close an issue."""
    api = GhApi(token=token)
    # Strangely the "pull_request" field of api.issues.get is often not set
    # so we have to go through the events to check if there's a commit
    events = api.issues.list_events(org, repo, issue_number)
    commit_urls = []
    for event in events:
        if event.event != "referenced":
            continue
        if not event.commit_id:
            continue
        commit = api.repos.get_commit(org, repo, event.commit_id)
        message = commit.commit.message
        if f"fixes #{issue_number}" in message.lower() or f"closes #{issue_number}" in message.lower():
            commit_urls.append(commit.html_url)
    return commit_urls


def remove_triple_backticks(text: str) -> str:
    return "\n".join(line.removeprefix("```") for line in text.splitlines())


def format_trajectory_markdown(trajectory: list[dict[str, str]]):
    """Format a trajectory as a markdown string for use in gh PR description."""
    prefix = [
        "<details>",
        "<summary>Thought process ('trajectory') of SWE-agent (click to expand)</summary>",
        "",
        "",
    ]
    steps = []
    for i, step in enumerate(trajectory):
        step_strs = [
            f"**🧑‍🚒 Response ({i})**: ",
            f"{step['response'].strip()}",
            f"**👀‍ Observation ({i})**:",
            "```",
            f"{remove_triple_backticks(step['observation']).strip()}",
            "```",
        ]
        steps.append("\n".join(step_strs))
    suffix = [
        "",
        "</details>",
    ]
    return "\n".join(prefix) + "\n\n---\n\n".join(steps) + "\n".join(suffix)


class PatchFormatter:
    def __init__(
        self,
        patch: str,
        read_method: Callable[[str], str],
    ):
        """Given the final patch and access to the container that contains the repository,
        extract relevant lines from the modified file.

        Args:
            patch: The patch as a string.
            read_method: Callable with path to file (relative to repository root) as argument
                that returns the file content as a string.
        """
        self._patch = PatchSet(patch)
        self._patched_files: dict[str, str] = {}
        self._original_files: dict[str, str] = {}
        self._patch_applied = True
        self._read_file = read_method
        self._read_files(original=False)

    @staticmethod
    def _merge_intervals(starts: list[int], stops: list[int]) -> tuple[list[int], list[int]]:
        """Given two lists of integers, starts and stops, merges all overlapping intervals.

        For example `starts=[1, 5, 18]`, `stops=[10, 13, 20]`
        should return `starts=[1, 18]`, `stops=[13, 20]`
        """

        intervals = sorted(zip(starts, stops))
        merged = []
        for start, stop in intervals:
            if not merged or merged[-1][1] < start:
                # No overlap
                merged.append([start, stop])
            else:
                # Overlap
                merged[-1][1] = max(merged[-1][1], stop)
        # Unzip again
        merged_starts, merged_stops = zip(*merged)
        return list(merged_starts), list(merged_stops)

    def format_file(self, text: str, starts: list[int], stops: list[int], *, linenos: bool = True) -> str:
        """Reads file and returns string representation of the relevant lines.

        Args:
            path: The path to the file within the repo location
            starts: The starting line numbers of the relevant lines. The first line is line 1.
            stops: The stopping line numbers of the relevant lines. The stop is not inclusive.
                The first line is line 1.
            linenos: Whether to include line numbers
        """
        assert len(starts) == len(stops)
        assert all(start >= 1 for start in starts)
        assert all(start < stop for start, stop in zip(starts, stops))
        starts, stops = self._merge_intervals(starts, stops)
        assert all(hunk1_start < hunk2_start for hunk1_start, hunk2_start in zip(starts, starts[1:]))
        out: list[str] = []
        if starts[0] > 1:
            # Count from 1
            out.append(f"[{starts[0]-1} lines above omitted]")
        last_stop: int | None = None
        lines = text.splitlines()
        for start, stop in zip(starts, stops):
            assert start >= 1
            if last_stop is not None:
                n_omitted = start - last_stop
                # Check that we have non-overlapping hunks
                assert n_omitted >= 0
                if n_omitted:
                    out.append(f"\n[{n_omitted} lines omitted]\n")
            # Count from 1
            these_lines = lines[start - 1 : stop - 1]
            if linenos:
                out.append("\n".join([f"{i:6d}: {l}" for i, l in enumerate(these_lines, start=start)]))
            else:
                out.append("\n".join(these_lines))
            last_stop = stop
        if last_stop < len(lines):
            # Stop is not inclusive
            omitted = len(lines) - last_stop
            assert omitted > 0
            out.append(f"[{omitted} lines below omitted]")
        return "\n".join(out)

    def _get_hunk_lines(self, original: bool, *, context_length: int) -> dict[str, tuple[list[int], list[int]]]:
        """Get the starts and stops for all files in the patch.

        Args:
            original: Whether to read the original file or the patched file
            context_length: The number of lines to include above and below the hunk

        Returns:
            A dictionary with the file path as key and a tuple of lists of starts and stops as value.
        """
        out: dict[str, tuple[list[int], list[int]]] = {}
        for patch in self._patch:
            if not patch.is_modified_file:
                continue
            starts: list[int] = []
            stops: list[int] = []
            for hunk in patch:
                if original:
                    # 1 is the lowest line number
                    start = max(1, hunk.source_start - context_length)
                    stop = hunk.source_start + hunk.source_length + context_length
                else:
                    start = max(1, hunk.target_start - context_length)
                    stop = hunk.target_start + hunk.target_length + context_length
                starts.append(start)
                stops.append(stop)
            out[patch.path] = (starts, stops)
        return out

    def _read_files(self, original: bool) -> None:
        for patch in self._patch:
            path = patch.path
            if not patch.is_modified_file:
                continue
            if original:
                msg = "Original file reading not implemented"
                raise NotImplementedError(msg)
            else:
                assert self._patch_applied
                self._patched_files[path] = self._read_file(path)

    @staticmethod
    def concat_files_strings(files: dict[str, str]) -> str:
        """Concatenate multiple `read_files` outputs into a single string."""
        out = []
        for path, content in files.items():
            out.append(f"[File: {path}]\n{content}")
        return "\n\n".join(out)

    def get_files_str(self, *, original: bool, context_length: int | None = 50, linenos: bool = True) -> str:
        hunk_lines = self._get_hunk_lines(original=original, context_length=context_length)
        sources = self._original_files if original else self._patched_files
        return self.concat_files_strings(
            {path: self.format_file(text, *hunk_lines[path], linenos=linenos) for path, text in sources.items()}
        )


def extract_flag_format(flag: str) -> str:
    flag_format = re.sub(r"{.*}$", "{...}", flag)
    return flag_format if flag_format != flag else "..."


def force_cleanup_all_ctf_resources() -> dict[str, int]:
    """
    Force cleanup of ALL CTF-related resources. 
    This is a comprehensive cleanup function that can be used for manual cleanup
    or in cleanup scripts. It mimics the behavior of the external cleanup script.
    
    Returns:
        Dictionary with counts of cleaned up resources
    """
    cleanup_stats = {
        "networks_removed": 0,
        "temp_files_removed": 0,
        "errors": 0
    }
    
    try:
        client = docker.from_env()
        
        # Find and remove all CTF networks (ctfnet-* and ctfnet)
        networks = client.networks.list()
        ctf_networks = [net for net in networks if net.name.startswith('ctfnet')]
        
        for network in ctf_networks:
            try:
                # Try to remove the network
                network.remove()
                cleanup_stats["networks_removed"] += 1
                logger.info(f"Removed CTF network: {network.name}")
            except docker.errors.APIError as e:
                if "has active endpoints" in str(e):
                    logger.warning(f"Network {network.name} has active containers, skipping")
                elif "not found" in str(e).lower():
                    logger.debug(f"Network {network.name} already removed")
                else:
                    logger.warning(f"Failed to remove network {network.name}: {e}")
                    cleanup_stats["errors"] += 1
            except Exception as e:
                logger.warning(f"Unexpected error removing network {network.name}: {e}")
                cleanup_stats["errors"] += 1
    
    except docker.errors.DockerException as e:
        logger.error(f"Docker error during comprehensive cleanup: {e}")
        cleanup_stats["errors"] += 1
    except Exception as e:
        logger.error(f"Unexpected error during comprehensive cleanup: {e}")
        cleanup_stats["errors"] += 1
    
    # Clean up temporary files
    try:
        import glob
        temp_files = glob.glob('/tmp/docker-compose-*')
        for temp_file in temp_files:
            try:
                Path(temp_file).unlink()
                cleanup_stats["temp_files_removed"] += 1
                logger.debug(f"Removed temporary file: {temp_file}")
            except FileNotFoundError:
                pass  # Already removed
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {temp_file}: {e}")
                cleanup_stats["errors"] += 1
    except Exception as e:
        logger.warning(f"Error during temporary file cleanup: {e}")
        cleanup_stats["errors"] += 1
    
    return cleanup_stats


def check_docker_subnet_availability(wait_for_space: bool = False, max_wait_time: int = 300) -> dict[str, int]:
    """
    Check Docker's subnet availability for informational purposes only.
    Subnet restrictions have been removed.
    
    Args:
        wait_for_space: Ignored (kept for compatibility)
        max_wait_time: Ignored (kept for compatibility)
    
    Returns:
        Dictionary with network counts and availability status
    """
    try:
        client = docker.from_env()
        networks = client.networks.list()
        
        # Count different types of networks
        total_networks = len(networks)
        bridge_networks = len([n for n in networks if n.attrs.get('Driver') == 'bridge'])
        dynamic_networks = len([n for n in networks if n.name.startswith('ctfnet-')])
        
        status = {
            'total_networks': total_networks,
            'bridge_networks': bridge_networks, 
            'dynamic_networks': dynamic_networks,
            'subnet_usage_warning': False,  # No longer enforce warnings
            'subnet_usage_critical': False  # No longer enforce restrictions
        }
        
        # Keep informational logging only
        logger.debug(f"Docker network status: {status}")
        logger.debug(f"Found {bridge_networks} bridge networks, {dynamic_networks} dynamic CTF networks")
        
        return status
        
    except Exception as e:
        logger.warning(f"Failed to check Docker subnet availability: {e}")
        return {'error': str(e)}


def wait_for_docker_subnet_space(
    max_wait_time: int = 300,  # 5 minutes default
    check_interval: int = 10,  # Check every 10 seconds
    target_free_networks: int = 5  # Target at least 5 free network slots
) -> bool:
    """
    No longer enforces subnet space restrictions - always returns True.
    This function is kept for compatibility but no longer waits or restricts.
    
    Args:
        max_wait_time: Ignored (kept for compatibility)
        check_interval: Ignored (kept for compatibility)
        target_free_networks: Ignored (kept for compatibility)
    
    Returns:
        bool: Always True (no restrictions)
    """
    logger.debug("Subnet space restrictions disabled - proceeding without limitations")
    return True


def check_network_restrictions_applied(container_name: str) -> bool:
    """
    Check if network restrictions are already applied to a container.
    
    Args:
        container_name: Name of the container to check
    
    Returns:
        bool: True if restrictions are applied, False otherwise
    """
    import docker
    
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        
        # Check if iptables rules are set up by looking for our specific rules
        exec_result = container.exec_run("iptables -L OUTPUT -n 2>/dev/null || echo 'NO_IPTABLES'")
        
        if exec_result.exit_code != 0:
            logger.debug(f"Could not check iptables rules in container {container_name}")
            return False
        
        output = exec_result.output.decode()
        
        # Check if our network restriction rules are present
        if "NO_IPTABLES" in output:
            logger.debug(f"iptables not available in container {container_name}")
            return False
        
        # Look for our specific rules that indicate restrictions are applied
        # We look for the default DROP policy and our REJECT rule
        if "policy DROP" in output and "REJECT" in output:
            logger.debug(f"Network restrictions already applied to container {container_name}")
            return True
        else:
            logger.debug(f"Network restrictions not found in container {container_name}")
            return False
            
    except Exception as e:
        logger.debug(f"Error checking network restrictions for container {container_name}: {e}")
        return False


def _setup_network_restrictions(container_name: str) -> None:
    """
    Set up STRICT network restrictions using iptables to:
    1. Allow localhost connections (for local services)
    2. Allow Docker internal network communications (for CTF challenges)
    3. Block ALL external internet connections (no public internet access)
    
    This ensures agents cannot:
    - Exfiltrate data to external servers
    - Download additional tools or packages
    - Call external APIs
    - Access any external resources
    
    While preserving CTF challenge connectivity to docker-compose services.
    
    Raises:
        RuntimeError: If network restrictions cannot be applied or validation fails
    """
    import subprocess
    import docker
    
    logger.info("🔒 Setting up STRICT network restrictions (preserving CTF connectivity, blocking external internet)")
    
    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        
        # First, check if the container supports iptables (writable filesystem)
        logger.debug(f"Checking if container {container_name} supports iptables...")
        
        # Test if we can write to filesystem
        filesystem_test = container.exec_run(
            ["sh", "-c", "touch /tmp/test_write 2>/dev/null && rm -f /tmp/test_write 2>/dev/null && echo 'FS_WRITABLE' || echo 'FS_READONLY'"],
            privileged=True
        )
        
        if filesystem_test.exit_code == 0 and b'FS_READONLY' in filesystem_test.output:
            error_msg = f"Container {container_name} has read-only filesystem - cannot apply network restrictions"
            logger.error(f"❌ SECURITY ERROR: {error_msg}")
            logger.error("❌ TERMINATING TASK: Cannot ensure network security")
            raise RuntimeError(f"Network security cannot be ensured: {error_msg}")
        
        # Test if iptables can write lock files
        iptables_test = container.exec_run(
            ["sh", "-c", "test -w /run 2>/dev/null && echo 'IPTABLES_WRITABLE' || echo 'IPTABLES_READONLY'"],
            privileged=True
        )
        
        if iptables_test.exit_code == 0 and b'IPTABLES_READONLY' in iptables_test.output:
            error_msg = f"Container {container_name} cannot write iptables lock files (/run is read-only)"
            logger.error(f"❌ SECURITY ERROR: {error_msg}")
            logger.error("❌ TERMINATING TASK: Cannot ensure network security")
            raise RuntimeError(f"Network security cannot be ensured: {error_msg}")
        
        logger.debug(f"✅ Container {container_name} supports iptables - proceeding with restrictions")
        
        # Execute iptables setup commands individually
        try:
            logger.info("🔧 Checking if iptables is available...")
            
            # First check if iptables is already installed
            iptables_check = container.exec_run(
                ["which", "iptables"],
                privileged=True
            )
            
            if iptables_check.exit_code != 0:
                logger.info("iptables not found, attempting to install...")
                
                # Install iptables only if not already present
                install_result = container.exec_run(
                    ["sh", "-c", "apt-get update -qq > /dev/null 2>&1 || true"],
                    privileged=True
                )
                
                install_result = container.exec_run(
                    ["sh", "-c", "apt-get install -y iptables iproute2 > /dev/null 2>&1"],
                    privileged=True
                )
                
                if install_result.exit_code != 0:
                    logger.error("❌ Failed to install iptables")
                    logger.error("❌ TERMINATING TASK: Cannot ensure network security")
                    raise RuntimeError("Failed to install iptables - network security cannot be ensured")
                
                logger.info("✅ iptables installed successfully")
            else:
                logger.info("✅ iptables already available")
            
            # Verify iptables is working
            iptables_version = container.exec_run(
                ["iptables", "--version"],
                privileged=True
            )
            
            if iptables_version.exit_code != 0:
                logger.error("❌ iptables is not functioning properly")
                logger.error("❌ TERMINATING TASK: Cannot ensure network security")
                raise RuntimeError("iptables is not functioning - network security cannot be ensured")
            
            logger.debug(f"iptables version: {iptables_version.output.decode().strip()}")
            
            logger.info("🔒 Applying network restrictions...")
            
            # Clear existing rules
            container.exec_run(["iptables", "-F", "OUTPUT"], privileged=True)
            container.exec_run(["iptables", "-X"], privileged=True)
            
            # Set default DROP policy
            policy_result = container.exec_run(["iptables", "-P", "OUTPUT", "DROP"], privileged=True)
            if policy_result.exit_code != 0:
                error_msg = f"Failed to set iptables DROP policy: {policy_result.output.decode()}"
                logger.error(f"❌ SECURITY ERROR: {error_msg}")
                logger.error("❌ TERMINATING TASK: Cannot ensure network security")
                raise RuntimeError(f"Network security cannot be ensured: {error_msg}")
            
            # Allow loopback traffic
            container.exec_run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], privileged=True)
            container.exec_run(["iptables", "-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "ACCEPT"], privileged=True)
            logger.debug("✓ Localhost traffic allowed")
            
            # Allow established connections
            container.exec_run(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], privileged=True)
            logger.debug("✓ Response traffic allowed")
            
            # Get Docker networks and allow them
            route_result = container.exec_run(["ip", "route", "show"], privileged=True)
            if route_result.exit_code == 0:
                routes = route_result.output.decode()
                logger.debug(f"Container routes: {routes}")
                
                # Extract Docker network ranges from routes
                import re
                docker_networks = re.findall(r'(172\.\d+\.\d+\.\d+/\d+|10\.\d+\.\d+\.\d+/\d+|192\.168\.\d+\.\d+/\d+)', routes)
                
                for network in docker_networks:
                    container.exec_run(["iptables", "-A", "OUTPUT", "-d", network, "-j", "ACCEPT"], privileged=True)
                    logger.debug(f"✓ Docker network allowed: {network}")
            
            # Allow common Docker network ranges
            common_networks = ["172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"]
            for network in common_networks:
                container.exec_run(["iptables", "-A", "OUTPUT", "-d", network, "-j", "ACCEPT"], privileged=True)
            logger.debug("✓ All Docker internal networks allowed")
            
            # Block all other traffic (external internet)
            reject_result = container.exec_run(["iptables", "-A", "OUTPUT", "-j", "REJECT", "--reject-with", "icmp-net-unreachable"], privileged=True)
            if reject_result.exit_code != 0:
                error_msg = f"Failed to set iptables REJECT rule: {reject_result.output.decode()}"
                logger.error(f"❌ SECURITY ERROR: {error_msg}")
                logger.error("❌ TERMINATING TASK: Cannot ensure network security")
                raise RuntimeError(f"Network security cannot be ensured: {error_msg}")
            
            logger.info("🚫 ALL external internet traffic blocked")
            
        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"❌ Failed to configure iptables: {e}")
            logger.error("❌ TERMINATING TASK: Cannot ensure network security")
            raise RuntimeError(f"iptables configuration failed: {e}")
        
        # CRITICAL VALIDATION: Test restrictions using individual commands
        logger.info("🔍 Validating network restrictions...")
        
        try:
            # Test 1: External internet should be blocked - use basic TCP connection test
            logger.debug("Testing external connectivity (should fail)...")
            
            # Use the most basic network test possible - direct TCP connection
            # This doesn't write any files and works purely in memory
            external_test = container.exec_run(
                ["timeout", "3", "bash", "-c", "echo > /dev/tcp/8.8.8.8/53"],
                privileged=True
            )
            
            if external_test.exit_code == 0:
                logger.error("❌ CRITICAL SECURITY ERROR: External connectivity test PASSED!")
                logger.error("❌ Network restrictions validation FAILED - external access is still possible")
                logger.error("❌ TERMINATING TASK: Cannot ensure agent security")
                raise RuntimeError("Network restrictions validation failed - external access is still possible. Task terminated for security.")
            else:
                logger.info("✅ External connectivity blocked as expected")
            
            # Test 2: Try another external test with different method
            logger.debug("Testing external HTTP connectivity (should fail)...")
            http_test = container.exec_run(
                ["timeout", "2", "bash", "-c", "echo > /dev/tcp/1.1.1.1/80"],
                privileged=True
            )
            
            if http_test.exit_code == 0:
                logger.error("❌ CRITICAL SECURITY ERROR: External HTTP connectivity test PASSED!")
                logger.error("❌ Network restrictions validation FAILED - external access is still possible")
                logger.error("❌ TERMINATING TASK: Cannot ensure agent security")
                raise RuntimeError("Network restrictions validation failed - external HTTP access is still possible. Task terminated for security.")
            else:
                logger.info("✅ External HTTP connectivity blocked as expected")
            
            # Test 3: Docker networks should work - test internal connectivity
            logger.debug("Testing Docker network connectivity...")
            docker_test_passed = False
            
            for gateway in ["172.17.0.1", "172.18.0.1", "172.19.0.1", "10.0.0.1"]:
                # Use basic TCP connection test for internal networks
                internal_test = container.exec_run(
                    ["timeout", "2", "bash", "-c", f"echo > /dev/tcp/{gateway}/22 || echo > /dev/tcp/{gateway}/53 || echo > /dev/tcp/{gateway}/80"],
                    privileged=True
                )
                if internal_test.exit_code == 0:
                    logger.debug(f"✅ Can reach Docker gateway: {gateway}")
                    docker_test_passed = True
                    break
            
            if not docker_test_passed:
                logger.warning("⚠️  Could not reach any Docker gateways - this may be normal depending on network setup")
            
            logger.info("✅ Network restrictions applied successfully")
            logger.info("🔒 External internet blocked, CTF connectivity preserved")
            
        except RuntimeError:
            raise
        except Exception as e:
            logger.error(f"❌ Network restrictions validation failed: {e}")
            logger.error("❌ TERMINATING TASK: Cannot ensure network security")
            raise RuntimeError(f"Network restrictions validation failed: {e}")
        
    except RuntimeError:
        # Re-raise RuntimeError exceptions (these are our intentional security failures)
        raise
    except Exception as e:
        logger.error(f"❌ Failed to apply network restrictions to challenge containers: {e}")
        logger.warning("⚠️  SECURITY WARNING: Challenge containers may have unrestricted network access!")
        logger.warning("   However, if they have read-only filesystems, this may be expected")


def _setup_network_restrictions_for_challenge_containers(docker_compose_path: Path, container_name_suffix: str) -> None:
    """
    Apply network restrictions to ALL containers created by docker-compose for CTF challenges.
    This is CRITICAL for security - challenge containers can also access external networks!
    
    Args:
        docker_compose_path: Path to the docker-compose file
        container_name_suffix: Suffix used for container names (to identify our containers)
    """
    import docker
    import yaml
    
    logger.info("🔒 Applying network restrictions to challenge containers...")
    
    try:
        # Read the docker-compose file to get service names
        with open(docker_compose_path, 'r') as f:
            compose_data = yaml.safe_load(f)
        
        client = docker.from_env()
        
        # Find all containers created by this docker-compose
        challenge_containers = []
        if 'services' in compose_data:
            for service_name in compose_data['services'].keys():
                # Container names follow the pattern: servicename-suffix
                container_name = f"{service_name}-{container_name_suffix}"
                try:
                    container = client.containers.get(container_name)
                    challenge_containers.append(container)
                    logger.debug(f"Found challenge container: {container_name}")
                except docker.errors.NotFound:
                    logger.debug(f"Challenge container not found: {container_name}")
                    continue
                except Exception as e:
                    logger.warning(f"Error accessing challenge container {container_name}: {e}")
                    continue
        
        # Apply network restrictions to each challenge container (with read-only detection)
        restrictions_applied = 0
        restrictions_skipped = 0
        for container in challenge_containers:
            try:
                logger.info(f"🔍 Checking if container {container.name} supports network restrictions...")
                
                # Check if container has a read-only filesystem by testing write access
                test_result = container.exec_run(
                    ["sh", "-c", "touch /tmp/writetest 2>/dev/null && rm -f /tmp/writetest 2>/dev/null && echo 'WRITABLE' || echo 'READONLY'"],
                    privileged=True
                )
                
                if test_result.exit_code == 0 and b'READONLY' in test_result.output:
                    logger.info(f"⚠️  Container {container.name} has read-only filesystem - skipping network restrictions")
                    logger.info(f"   (Challenge containers with read-only filesystems cannot use iptables)")
                    logger.info(f"   (This is normal for many CTF challenge containers)")
                    restrictions_skipped += 1
                    continue
                    
                # Also check if iptables can write its lock file
                iptables_test = container.exec_run(
                    ["sh", "-c", "test -w /run 2>/dev/null && echo 'IPTABLES_OK' || echo 'IPTABLES_READONLY'"],
                    privileged=True
                )
                
                if iptables_test.exit_code == 0 and b'IPTABLES_READONLY' in iptables_test.output:
                    logger.info(f"⚠️  Container {container.name} cannot write iptables lock files - skipping network restrictions")
                    logger.info(f"   (/run directory is read-only, iptables cannot function)")
                    restrictions_skipped += 1
                    continue
                
                logger.info(f"✅ Container {container.name} supports network restrictions - applying...")
                _setup_network_restrictions(container.name)
                restrictions_applied += 1
                
            except Exception as e:
                logger.warning(f"❌ Failed to apply network restrictions to challenge container {container.name}: {e}")
                logger.warning(f"   This may be due to read-only filesystem or security restrictions")
                restrictions_skipped += 1
                # Continue with other containers even if one fails
        
        if restrictions_applied > 0:
            logger.info(f"✅ Applied network restrictions to {restrictions_applied} challenge containers")
        if restrictions_skipped > 0:
            logger.info(f"ℹ️  Skipped {restrictions_skipped} challenge containers (read-only filesystems)")
            logger.info(f"   Challenge containers with read-only filesystems are common and expected")
            logger.info(f"   Network restrictions are still applied to the main agent container")
        if restrictions_applied == 0 and restrictions_skipped == 0:
            logger.warning("⚠️  No challenge containers found for network restrictions")
            
    except Exception as e:
        logger.error(f"❌ Failed to apply network restrictions to challenge containers: {e}")
        logger.warning("⚠️  SECURITY WARNING: Challenge containers may have unrestricted network access!")
        logger.warning("   However, if they have read-only filesystems, this may be expected")
