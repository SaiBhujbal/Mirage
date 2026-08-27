#!/bin/bash
# Verify Testing Setup - Check all test files are in place

echo "╔════════════════════════════════════════════════════════════╗"
echo "║      DECEPTICON WAF - Testing Setup Verification         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

total_checks=0
passed_checks=0

# Function to check file exists
check_file() {
    ((total_checks++))
    if [ -f "$1" ]; then
        echo "  ✅ $1"
        ((passed_checks++))
    else
        echo "  ❌ MISSING: $1"
    fi
}

# Check ONNX conversion script
echo "1. ONNX Conversion Script"
echo "────────────────────────────────────────"
check_file "ml/convert_to_onnx.py"
echo ""

# Check test scripts
echo "2. Test Scripts (tests/security/)"
echo "────────────────────────────────────────"
check_file "tests/security/run_quick_tests.sh"
check_file "tests/security/test_ml_layer.sh"
check_file "tests/security/test_all_layers.sh"
check_file "tests/security/test_zero_day.sh"
check_file "tests/security/test_performance.sh"
check_file "tests/security/test_compliance.sh"
echo ""

# Check documentation
echo "3. Documentation Files"
echo "────────────────────────────────────────"
check_file "docs/COMPREHENSIVE_SECURITY_TEST.md"
check_file "tests/security/README.md"
check_file "tests/QUICK_START_TESTING.md"
check_file "TESTING_DELIVERABLES.md"
echo ""

# Check if test scripts are executable
echo "4. Executable Permissions"
echo "────────────────────────────────────────"

executable_count=0
for script in tests/security/*.sh; do
    if [ -x "$script" ]; then
        ((executable_count++))
    fi
done

if [ $executable_count -eq 6 ]; then
    echo "  ✅ All 6 test scripts are executable"
    ((passed_checks++))
    ((total_checks++))
else
    echo "  ⚠️  Only $executable_count/6 scripts are executable"
    echo "     Run: chmod +x tests/security/*.sh"
    ((total_checks++))
fi
echo ""

# Check dependencies
echo "5. System Dependencies"
echo "────────────────────────────────────────"

((total_checks++))
if command -v curl &> /dev/null; then
    echo "  ✅ curl installed"
    ((passed_checks++))
else
    echo "  ❌ curl not found (required for tests)"
fi

((total_checks++))
if command -v jq &> /dev/null; then
    echo "  ✅ jq installed"
    ((passed_checks++))
else
    echo "  ❌ jq not found (required for tests)"
fi

((total_checks++))
if command -v bc &> /dev/null; then
    echo "  ✅ bc installed"
    ((passed_checks++))
else
    echo "  ❌ bc not found (required for tests)"
fi

((total_checks++))
if command -v python3 &> /dev/null; then
    echo "  ✅ python3 installed"
    ((passed_checks++))
else
    echo "  ❌ python3 not found (required for ONNX conversion)"
fi

echo ""

# Check Python packages for ONNX conversion
echo "6. Python ONNX Dependencies (Optional)"
echo "────────────────────────────────────────"

python3 -c "import onnx" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  ✅ onnx installed"
else
    echo "  ⚠️  onnx not installed (optional - for ONNX conversion)"
    echo "     Install: pip install onnx onnxruntime skl2onnx onnxmltools"
fi

python3 -c "import onnxruntime" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "  ✅ onnxruntime installed"
else
    echo "  ⚠️  onnxruntime not installed (optional - for ONNX conversion)"
fi

echo ""

# Check if WAF is running
echo "7. WAF Status"
echo "────────────────────────────────────────"

waf_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/waf/health 2>/dev/null || echo "000")

if [ "$waf_status" = "200" ]; then
    echo "  ✅ WAF is running on http://localhost:8080"
    echo "     Tests are ready to run!"
else
    echo "  ⚠️  WAF is not running (HTTP $waf_status)"
    echo "     Start WAF: python3 main.py"
fi

echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  VERIFICATION SUMMARY                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Checks passed: $passed_checks / $total_checks"
echo ""

if [ $passed_checks -ge 14 ]; then
    echo "✅ TESTING SETUP COMPLETE"
    echo ""
    echo "All required files are in place!"
    echo ""
    echo "Next Steps:"
    echo "  1. Start WAF (if not running): python3 main.py"
    echo "  2. Run tests: cd tests/security && ./run_quick_tests.sh"
    echo "  3. View results and documentation"
    echo ""
    echo "Quick Links:"
    echo "  • Quick start guide: tests/QUICK_START_TESTING.md"
    echo "  • Test suite README: tests/security/README.md"
    echo "  • Full test docs: docs/COMPREHENSIVE_SECURITY_TEST.md"
    echo "  • Deliverables summary: TESTING_DELIVERABLES.md"
    echo ""
    exit 0
else
    echo "⚠️  SOME ISSUES DETECTED"
    echo ""
    echo "Required actions:"

    if ! command -v curl &> /dev/null || ! command -v jq &> /dev/null || ! command -v bc &> /dev/null; then
        echo "  • Install missing dependencies:"
        echo "    - Ubuntu/Debian: sudo apt-get install curl jq bc"
        echo "    - macOS: brew install curl jq bc"
    fi

    if [ $executable_count -lt 6 ]; then
        echo "  • Make test scripts executable: chmod +x tests/security/*.sh"
    fi

    if [ "$waf_status" != "200" ]; then
        echo "  • Start WAF: python3 main.py"
    fi

    echo ""
    exit 1
fi
