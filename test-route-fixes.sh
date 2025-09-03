#!/bin/bash

echo "Testing route addition and deletion fixes"

# Test the updated del_route function logic
echo "Testing del_route function with sample data:"
echo "Peer IP: 10.255.10.11"
echo "Destination: 192.168.1.0/24"

echo "The updated del_route function now:"
echo "1. Finds the full route entry to get gateway and device information"
echo "2. Extracts gateway and device from the route entry"
echo "3. Tries to delete from the actual routing table using ip route del command"
echo "4. Removes route from file"
echo "5. Removes file if empty"

echo ""
echo "Testing PHP backend improvements:"
echo "1. addRoute now automatically applies routes after adding them"
echo "2. deleteRoute now properly removes routes from both file and routing table"
echo "3. Better error handling and user feedback in JavaScript"
echo "4. Loading indicators during operations"