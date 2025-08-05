# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/usr/bin/env bash

#
docker build --platform linux/amd64 -f docker/swe-ctf.Dockerfile -t sweagent/swe-ctf:latest  .
docker network create ctfnet