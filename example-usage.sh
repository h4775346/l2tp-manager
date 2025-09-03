#!/bin/bash

# Example usage of the L2TP per-user routing system

echo "Example Usage of L2TP Per-User Routing System"

# Example 1: Add a route for user with peer IP 10.255.10.11
echo "Adding route for user 10.255.10.11..."
sudo /usr/local/sbin/l2tp-routectl add --peer 10.255.10.11 --dst 192.168.1.0/24

# Example 2: Add a route with custom gateway
echo "Adding route with custom gateway..."
sudo /usr/local/sbin/l2tp-routectl add --peer 10.255.10.12 --dst 10.0.0.0/8 --gw 10.255.10.1

# Example 3: List all routes
echo "Listing all routes..."
sudo /usr/local/sbin/l2tp-routectl list

# Example 4: List routes for specific peer
echo "Listing routes for peer 10.255.10.11..."
sudo /usr/local/sbin/l2tp-routectl list --peer 10.255.10.11

# Example 5: Apply routes for specific peer
echo "Applying routes for peer 10.255.10.11..."
sudo /usr/local/sbin/l2tp-routectl apply --peer 10.255.10.11

# Example 6: Delete a route
echo "Deleting route for 192.168.1.0/24 from peer 10.255.10.11..."
sudo /usr/local/sbin/l2tp-routectl del --peer 10.255.10.11 --dst 192.168.1.0/24

# Example 7: List routes again to verify deletion
echo "Listing all routes after deletion..."
sudo /usr/local/sbin/l2tp-routectl list