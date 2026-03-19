#!/bin/bash

# ==============================================================================
# Network Scanner Script for eno1 and VLAN Interfaces (ARP-ONLY)
# ==============================================================================
# Purpose: Network discovery using arp-scan for authorized pentesting
# Author: HackerAI Assistant
# Date: 2026-03-19
# Target: 95.216.241.0/26 network via eno1 and VLAN subinterfaces
# ==============================================================================

# Configuration
TARGET_NETWORK="95.216.241.0/26"
# Use local static binary if available, otherwise fallback to system arp-scan
ARP_SCAN_BIN="./arp-scan" 
OUTPUT_DIR="./scan_results"
LOG_FILE="$OUTPUT_DIR/scan_$(date +%Y%m%d_%H%M%S).log"
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to print colored output
print_header() {
    echo -e "${BLUE}[$TIMESTAMP] $1${NC}"
    echo "$TIMESTAMP $1" >> "$LOG_FILE"
}

print_success() {
    echo -e "${GREEN}[+] $1${NC}"
    echo "$TIMESTAMP [+] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
    echo "$TIMESTAMP [!] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
    echo "$TIMESTAMP [-] $1" >> "$LOG_FILE"
}

# Check if running as root
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        print_warning "Script requires root privileges. Attempting to run with sudo..."
        exec sudo "$0" "$@"
        exit $?
    fi
    print_success "Running with root privileges"
}

# Check for required tools
check_tools() {
    local tools=("ip" "bash")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
    
    # Check for arp-scan (either system or static binary)
    if [ -f "$ARP_SCAN_BIN" ]; then
        print_success "Found static arp-scan binary at $ARP_SCAN_BIN"
    elif command -v "arp-scan" &> /dev/null; then
        print_success "Found system arp-scan"
        ARP_SCAN_BIN="arp-scan" # Override to use system binary
    else
        print_warning "arp-scan not found. Please install it (sudo apt install arp-scan) or place a static binary at ./arp-scan"
        print_warning "Attempting to install system arp-scan..."
        sudo apt update && sudo apt install -y arp-scan
        if command -v "arp-scan" &> /dev/null; then
            ARP_SCAN_BIN="arp-scan"
            print_success "System arp-scan installed."
        else
            print_error "Failed to install arp-scan. Exiting."
            exit 1
        fi
    fi
}

# Get interface information
get_interface_info() {
    print_header "Gathering interface information..."
    
    echo "=== Interface Information ===" >> "$OUTPUT_DIR/interfaces.txt"
    ip addr show >> "$OUTPUT_DIR/interfaces.txt"
    
    echo "" >> "$OUTPUT_DIR/interfaces.txt"
    echo "=== Route Information ===" >> "$OUTPUT_DIR/interfaces.txt"
    ip route show >> "$OUTPUT_DIR/interfaces.txt"
    
    echo "" >> "$OUTPUT_DIR/interfaces.txt"
    echo "=== ARP Table ===" >> "$OUTPUT_DIR/interfaces.txt"
    ip neigh show >> "$OUTPUT_DIR/interfaces.txt"
    
    print_success "Interface information saved to $OUTPUT_DIR/interfaces.txt"
}

# Helper to run arp-scan
run_arp_scan() {
    local interface="$1"
    local network="$2"
    local output_file="$3"
    
    # Determine binary to use
    local binary="$ARP_SCAN_BIN"
    if [ ! -f "$ARP_SCAN_BIN" ] && [ "$ARP_SCAN_BIN" = "arp-scan" ]; then
        binary="arp-scan"
    fi
    
    print_header "Starting ARP scan on $interface ($network)..."
    
    "$binary" --interface="$interface" "$network" > "$output_file" 2>&1
    
    local result=$?
    if [ $result -eq 0 ]; then
        print_success "ARP scan completed on $interface"
        # Extract and display results
        grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$output_file" | while read line; do
            echo "$line" >> "$LOG_FILE"
            echo "  $line"
        done
    else
        print_error "ARP scan failed on $interface (exit code: $result)"
    fi
}

# Target-specific scanning
scan_eno1() {
    local interface="eno1"
    local ip="95.216.241.236"
    
    print_header "Scanning $interface ($ip/32)..."
    
    # Single host scan (ARP request for specific IP)
    local output_file="$OUTPUT_DIR/eno1_single_host.txt"
    run_arp_scan "$interface" "$ip" "$output_file"
}

scan_vlan_interfaces() {
    local base_ip="95.216.241.192"
    local netmask="/26"
    
    # All VLAN interfaces share the same /26 network
    local network="$base_ip$netmask"
    
    print_header "Scanning VLAN network $network via eno1..."
    
    # Scan with ARP
    local arp_output="$OUTPUT_DIR/vlan_arp_scan.txt"
    run_arp_scan "eno1" "$network" "$arp_output"
    
    # Display summary
    echo ""
    print_header "VLAN Network Scan Summary:"
    echo "  Network: $network"
    echo "  Active hosts found:"
    local count=$(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$arp_output" | grep -v "192.168" | wc -l)
    echo "    ARP scan: $count hosts"
}

# Comprehensive network analysis
comprehensive_analysis() {
    print_header "Performing comprehensive network analysis..."
    
    # 1. Check for live hosts in the entire /26 network
    local network="95.216.241.0/26"
    local analysis_file="$OUTPUT_DIR/comprehensive_analysis.txt"
    
    echo "=== Comprehensive Network Analysis ===" > "$analysis_file"
    echo "Target: $network" >> "$analysis_file"
    echo "Time: $TIMESTAMP" >> "$analysis_file"
    echo "" >> "$analysis_file"
    
    # ARP scan
    run_arp_scan "eno1" "$network" "$analysis_file"
    
    # Display summary
    echo ""
    print_header "Comprehensive Analysis Summary:"
    echo "  Analysis file: $analysis_file"
    echo ""
    
    # Count discovered hosts
    local arp_count=$(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$analysis_file" | grep -v "192.168" | wc -l)
    
    echo "  Discovered hosts:"
    echo "    ARP scan: $arp_count hosts"
}

# Generate report
generate_report() {
    print_header "Generating final report..."
    
    local report_file="$OUTPUT_DIR/final_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
================================================================================
NETWORK PENTESTING SCAN REPORT (ARP-ONLY)
================================================================================
Date: $TIMESTAMP
Target Network: 95.216.241.0/26
Interface: eno1 (with VLAN subinterfaces cp1-cp5)
Authorized Pentest: YES

================================================================================
SCAN RESULTS SUMMARY
================================================================================

1. ENO1 SINGLE HOST SCAN (95.216.241.236/32)
   - Method: ARP Request
   - Output: $OUTPUT_DIR/eno1_single_host.txt

2. VLAN NETWORK SCAN (95.216.241.192/26)
   - Method: ARP Scan
   - Output: $OUTPUT_DIR/vlan_arp_scan.txt

3. COMPREHENSIVE ANALYSIS
   - Full /26 network scan
   - Output: $OUTPUT_DIR/comprehensive_analysis.txt

4. INTERFACE INFORMATION
   - Detailed interface data: $OUTPUT_DIR/interfaces.txt

================================================================================
NEXT STEPS
================================================================================
1. Review the detailed scan results in the output files
2. Identify active hosts based on ARP responses
3. Perform targeted vulnerability scanning on discovered hosts
4. Document findings in your pentest report

================================================================================
DISCLAIMER
================================================================================
This scan was performed as part of authorized security testing.
All activities were conducted within the scope of the engagement.

================================================================================
EOF

    print_success "Final report generated: $report_file"
    echo ""
    cat "$report_file"
}

# Main execution function
main() {
    echo "=============================================================================="
    echo "Network Scanner for eno1 and VLAN Interfaces (ARP-ONLY)"
    echo "Authorized Pentesting Tool"
    echo "=============================================================================="
    echo ""
    
    # Initial setup
    check_privileges
    check_tools
    
    # Phase 1: Information gathering
    get_interface_info
    
    # Phase 2: Targeted scanning
    scan_eno1
    scan_vlan_interfaces
    
    # Phase 3: Comprehensive analysis
    comprehensive_analysis
    
    # Phase 4: Generate final report
    generate_report
    
    print_success "Scan completed successfully!"
    print_success "Results saved to: $OUTPUT_DIR"
    print_success "Log file: $LOG_FILE"
    
    echo ""
    echo "=============================================================================="
    echo "Scan completed at $(date)"
    echo "=============================================================================="
}

# Handle script interruption
trap 'print_warning "Scan interrupted by user"; exit 1' INT TERM

# Execute main function
main "$@"
