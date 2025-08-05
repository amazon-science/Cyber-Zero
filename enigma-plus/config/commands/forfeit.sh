# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#
# @yaml
# signature: exit_forfeit
# docstring: Give up on the current challenge and terminate the session.
# arguments:
exit_forfeit() {
    echo "Forfeit 😥"
    # Implementation note: This is actually caught directly in swe_env.py
    # We only include this stub so that the command is shown to the agent.
}