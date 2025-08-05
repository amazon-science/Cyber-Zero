# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.  

# SPDX-License-Identifier: CC-BY-NC-4.0


#!/bin/bash

#
# Automated test for edit command summarization blocking

echo "🧪 Testing edit command summarization blocking..."

# Create test directory
mkdir -p /tmp/edit_test
cd /tmp/edit_test

# Test file content that generates >100 lines
cat > test_generator.py << 'EOF'
#!/usr/bin/env python3
print("=" * 50)
print("TESTING SUMMARIZER WITH LONG OUTPUT")
print("=" * 50)
for i in range(1, 121):  # 120+ lines to trigger summarizer
    print(f"Output line {i:3d}: This is test output line {i}")
    if i % 20 == 0:
        print(f"    --> Checkpoint at line {i}")
print("=" * 50)
print("END OF LONG OUTPUT - Should have triggered summarizer")
print("=" * 50)
EOF

chmod +x test_generator.py

echo "✅ Created test_generator.py"
echo "📁 Test files created in: $(pwd)"
echo ""
echo "🔧 Now run these commands in your SWE-agent environment:"
echo "   1. cd $(pwd)"
echo "   2. open test_generator.py"
echo "   3. edit 1:5"
echo "      [make some changes]"
echo "      end_of_edit"
echo "   4. python test_generator.py  # Should trigger summarizer"
echo "   5. edit 10:15  # Should show clean file content"
echo "      [make more changes]" 
echo "      end_of_edit"
echo ""
echo "✅ Expected: All edit commands show clean file context"
echo "❌ Bug would be: Mixed content from previous summary"
