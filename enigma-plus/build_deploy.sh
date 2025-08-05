# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
# !bin/bash

python3 -m build

python3 -m twine upload --skip-existing --repository pypi dist/*