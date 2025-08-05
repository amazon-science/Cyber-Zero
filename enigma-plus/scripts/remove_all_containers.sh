# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/bin/bash

#
# Remove all docker containers

docker rm -f $(docker ps -aq)
