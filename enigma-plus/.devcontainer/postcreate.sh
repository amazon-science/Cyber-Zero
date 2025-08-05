# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env bash

#
set -euo pipefail
set -x

pip install -e '.'
docker pull sweagent/swe-agent
