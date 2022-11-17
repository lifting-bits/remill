# Copyright (c) 2022 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Post-process an assembly file and replace all @N@ symbols with newlines.

In Remill, we use pre-processor macros to generate assembly code. However,
macros cannot expand across multiple lines so there isn't a way to delimit
statements. To get around this limitation, we use the @N@ symbol to represent
a new line in the macro expansion and then use this post-processing script to
translate them into actual newlines.

Usage: post_process_asm.py INPUT_FILE OUTPUT_FILE
"""

import sys

with open(sys.argv[1]) as pre_processed, open(sys.argv[2], "w") as post_processed:
    for line in pre_processed:
        line = line.replace("@N@", "\n")
        post_processed.write(line)
