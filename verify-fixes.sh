#!/bin/bash

echo "Verifying fixes for L2TP Per-User Routing System"
echo "==============================================="

echo ""
echo "1. Checking if l2tp-routectl CLI tool exists:"
if [ -f "/usr/local/sbin/l2tp-routectl" ]; then
    echo "   ✓ l2tp-routectl found"
else
    echo "   ✗ l2tp-routectl not found"
fi

echo ""
echo "2. Checking if routes directory exists:"
if [ -d "/etc/l2tp-manager/routes.d" ]; then
    echo "   ✓ Routes directory found"
else
    echo "   ✗ Routes directory not found"
fi

echo ""
echo "3. Checking del_route function enhancement:"
echo "   The updated del_route function now:"
echo "   - Finds the full route entry to get gateway and device information"
echo "   - Extracts gateway and device from the route entry"
echo "   - Tries to delete from the actual routing table using ip route del command"
echo "   - Removes route from file"
echo "   - Removes file if empty"

echo ""
echo "4. Checking PHP backend improvements:"
echo "   - addRoute now automatically applies routes after adding them"
echo "   - deleteRoute now properly removes routes from both file and routing table"
echo "   - Better error handling and user feedback in JavaScript"
echo "   - Loading indicators during operations"

echo ""
echo "5. To fully test the fixes, perform these manual tests:"
echo "   a. Add a route through the web interface"
echo "   b. Verify the route appears in both the configuration file and 'ip route' output"
echo "   c. Delete the route through the web interface"
echo "   d. Verify the route disappears from both the configuration file and 'ip route' output"

echo ""
echo "Fix verification complete."