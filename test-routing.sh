#!/bin/bash

# Test script for the L2TP per-user routing system

echo "Testing L2TP Per-User Routing System..."

# Check if the l2tp-routectl tool exists
if [ ! -f "/usr/local/sbin/l2tp-routectl" ]; then
    echo "FAIL: l2tp-routectl tool not found"
    exit 1
fi

echo "PASS: l2tp-routectl tool found"

# Check if the tool is executable
if [ ! -x "/usr/local/sbin/l2tp-routectl" ]; then
    echo "FAIL: l2tp-routectl tool is not executable"
    exit 1
fi

echo "PASS: l2tp-routectl tool is executable"

# Test help command
echo "Testing help command..."
/usr/local/sbin/l2tp-routectl 2>&1 | grep -q "Usage"
if [ $? -eq 0 ]; then
    echo "PASS: Help command works"
else
    echo "FAIL: Help command failed"
fi

# Test add route command (dry run)
echo "Testing add route command syntax..."
/usr/local/sbin/l2tp-routectl add --peer 10.255.10.11 --dst 192.168.1.0/24 2>&1 | grep -q "Error"
if [ $? -eq 1 ]; then  # grep returns 1 when pattern not found, meaning no error
    echo "PASS: Add route command syntax is correct"
else
    echo "FAIL: Add route command syntax is incorrect"
fi

# Test list command
echo "Testing list command..."
/usr/local/sbin/l2tp-routectl list 2>&1 >/dev/null
if [ $? -eq 0 ]; then
    echo "PASS: List command works"
else
    echo "FAIL: List command failed"
fi

echo "Routing system test completed."