# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env bash

#
# bash strict mode
set -euo pipefail

echo "Setting up EnIGMA+ docker images for CTF challenges..."

# Build the main EnIGMA agent image
docker build -t sweagent/swe-agent:latest -f docker/swe.Dockerfile --build-arg TARGETARCH=$(uname -m) .

# Build the CTF-specific image
docker build --platform linux/amd64 -f docker/swe-ctf.Dockerfile -t sweagent/enigma:latest .

# Create CTF network for parallel execution
docker network create ctfnet 2>/dev/null || echo "CTF network already exists"

echo "Done with EnIGMA+ setup!"
echo "You can now run CTF challenges with: python run.py --ctf --image_name sweagent/enigma:latest"
