# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/bin/bash

#
echo "🧹 Container and Network Cleanup Script"
echo "========================================"

# Function to safely run commands and handle errors
safe_run() {
    local cmd="$1"
    local description="$2"
    
    echo "🔄 $description..."
    if eval "$cmd" 2>/dev/null; then
        echo "   ✅ Success"
    else
        echo "   ⚠️  No items to clean or operation failed (this is usually okay)"
    fi
}

echo ""
echo "📊 Current Status:"
echo "Containers running: $(docker ps -q | wc -l)"
echo "Total containers: $(docker ps -a -q | wc -l)"
echo "Networks: $(docker network ls | grep ctfnet | wc -l) ctfnet networks"

echo ""
echo "🛑 Step 1: Stopping all running containers (except sglang)..."
safe_run "docker ps -q --filter 'ancestor=lmsysorg/sglang' --filter 'status=running' --format '{{.ID}}' | xargs -r docker stop" "Stopping all running containers except sglang"

echo ""
echo "🗑️  Step 2: Removing all containers (except sglang)..."
safe_run "docker ps -a -q --filter 'ancestor=lmsysorg/sglang' --format '{{.ID}}' | xargs -r docker rm" "Removing all stopped containers except sglang"

echo ""
echo "🌐 Step 3: Removing CTF networks..."
# Remove all ctfnet-* networks (dynamic networks)
safe_run "docker network ls --format '{{.Name}}' | grep '^ctfnet-' | xargs -r docker network rm" "Removing dynamic ctfnet networks"

# Try to remove the base ctfnet network (might be in use, that's okay)
safe_run "docker network rm ctfnet" "Removing base ctfnet network"

echo ""
echo "🧽 Step 4: Cleaning up system resources..."
safe_run "docker system prune -f" "Cleaning up unused resources"

echo ""
echo "🔍 Step 5: Removing any leftover temporary files..."
safe_run "rm -f /tmp/docker-compose-*" "Removing temporary docker-compose files"

echo ""
echo "📊 Final Status:"
echo "Containers running: $(docker ps -q | wc -l)"
echo "Total containers: $(docker ps -a -q | wc -l)"
echo "CTF networks: $(docker network ls | grep ctfnet | wc -l)"

echo ""
if [ "$(docker ps -q --filter 'ancestor=lmsysorg/sglang' | wc -l)" -eq 0 ] && [ "$(docker ps -a -q --filter 'ancestor=lmsysorg/sglang' | wc -l)" -eq 0 ]; then
    echo "🎉 Cleanup completed successfully! All containers (except sglang) removed."
else
    echo "⚠️  Some containers may still be present. Check with 'docker ps -a'"
fi

echo ""
echo "🔧 If you need to forcefully remove everything (except sglang), run:"
echo "   docker ps -q --filter 'ancestor=lmsysorg/sglang' | xargs -r docker kill"
echo "   docker ps -a -q --filter 'ancestor=lmsysorg/sglang' | xargs -r docker rm -f"
echo "   docker network prune -f"
echo "   docker system prune -a -f" 