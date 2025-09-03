#!/bin/bash

# L2TP Per-User Routing System Installation Script
# This script installs all components required for per-user routing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Installing L2TP Per-User Routing System...${NC}"

# Create required directories
echo -e "${YELLOW}Creating directories...${NC}"
sudo mkdir -p /etc/l2tp-manager/routes.d
sudo mkdir -p /usr/local/sbin

# Create the l2tp-routectl CLI tool
echo -e "${YELLOW}Creating l2tp-routectl CLI tool...${NC}"
sudo tee /usr/local/sbin/l2tp-routectl > /dev/null << 'EOF'
#!/bin/bash

# l2tp-routectl - CLI tool for managing per-user routes
# Usage: l2tp-routectl [command] [options]

set -e

ROUTES_DIR="/etc/l2tp-manager/routes.d"
ROUTES_FILE_EXT=".routes"

# Function to display usage
usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  add --peer <peer_ip> --dst <CIDR> [--gw <ip>] [--dev <iface>]"
    echo "  del --peer <peer_ip> --dst <CIDR>"
    echo "  list [--peer <peer_ip>]"
    echo "  apply [--peer <peer_ip>]"
    echo ""
    echo "Examples:"
    echo "  $0 add --peer 10.255.10.11 --dst 10.255.10.0/24"
    echo "  $0 add --peer 10.255.10.11 --dst 192.168.1.0/24 --gw 10.255.10.1"
    echo "  $0 del --peer 10.255.10.11 --dst 10.255.10.0/24"
    echo "  $0 list"
    echo "  $0 list --peer 10.255.10.11"
    echo "  $0 apply --peer 10.255.10.11"
    exit 1
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

# Function to validate CIDR
validate_cidr() {
    local cidr=$1
    if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip=$(echo $cidr | cut -d'/' -f1)
        local prefix=$(echo $cidr | cut -d'/' -f2)
        if validate_ip $ip && [[ $prefix -ge 0 && $prefix -le 32 ]]; then
            return 0
        fi
    fi
    return 1
}

# Function to add a route
add_route() {
    local peer_ip=$1
    local dst_cidr=$2
    local gateway=$3
    local device=$4
    
    # Validate inputs
    if ! validate_ip $peer_ip; then
        echo "Error: Invalid peer IP address: $peer_ip"
        exit 1
    fi
    
    if ! validate_cidr $dst_cidr; then
        echo "Error: Invalid destination CIDR: $dst_cidr"
        exit 1
    fi
    
    if [[ -n "$gateway" ]] && ! validate_ip $gateway; then
        echo "Error: Invalid gateway IP address: $gateway"
        exit 1
    fi
    
    # Set default gateway to peer IP if not provided
    if [[ -z "$gateway" ]]; then
        gateway=$peer_ip
    fi
    
    # Create route entry
    local route_entry
    if [[ -n "$device" ]]; then
        route_entry="$dst_cidr via $gateway dev $device"
    else
        route_entry="$dst_cidr via $gateway"
    fi
    
    # Create peer routes file if it doesn't exist
    local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
    sudo mkdir -p $ROUTES_DIR
    
    # Check if route already exists to ensure idempotency
    if [[ -f "$routes_file" ]] && grep -q "^$route_entry$" "$routes_file"; then
        echo "Route already exists: $route_entry"
        return 0
    fi
    
    # Add route to file
    echo "$route_entry" | sudo tee -a "$routes_file" > /dev/null
    echo "Added route: $route_entry"
}

# Function to delete a route
del_route() {
    local peer_ip=$1
    local dst_cidr=$2
    
    # Validate inputs
    if ! validate_ip $peer_ip; then
        echo "Error: Invalid peer IP address: $peer_ip"
        exit 1
    fi
    
    if ! validate_cidr $dst_cidr; then
        echo "Error: Invalid destination CIDR: $dst_cidr"
        exit 1
    fi
    
    local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
    
    if [[ ! -f "$routes_file" ]]; then
        echo "No routes file found for peer: $peer_ip"
        return 0
    fi
    
    # Remove route from file
    sudo sed -i "\|^$dst_cidr|d" "$routes_file"
    echo "Deleted route with destination: $dst_cidr"
    
    # Remove file if empty
    if [[ ! -s "$routes_file" ]]; then
        sudo rm -f "$routes_file"
        echo "Removed empty routes file for peer: $peer_ip"
    fi
}

# Function to list routes
list_routes() {
    local peer_ip=$1
    
    if [[ -n "$peer_ip" ]]; then
        # List routes for specific peer
        if ! validate_ip $peer_ip; then
            echo "Error: Invalid peer IP address: $peer_ip"
            exit 1
        fi
        
        local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
        if [[ -f "$routes_file" ]]; then
            echo "Routes for peer $peer_ip:"
            cat "$routes_file"
        else
            echo "No routes found for peer: $peer_ip"
        fi
    else
        # List all routes
        if [[ -d "$ROUTES_DIR" ]] && [[ -n "$(ls -A $ROUTES_DIR)" ]]; then
            echo "All routes:"
            for file in $ROUTES_DIR/*$ROUTES_FILE_EXT; do
                if [[ -f "$file" ]]; then
                    local filename=$(basename "$file")
                    local peer=$(echo "$filename" | sed "s|$ROUTES_FILE_EXT$||")
                    echo "Peer: $peer"
                    cat "$file"
                    echo ""
                fi
            done
        else
            echo "No routes found"
        fi
    fi
}

# Function to apply routes for a peer
apply_routes() {
    local peer_ip=$1
    
    # Validate input
    if ! validate_ip $peer_ip; then
        echo "Error: Invalid peer IP address: $peer_ip"
        exit 1
    fi
    
    local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
    
    if [[ ! -f "$routes_file" ]]; then
        echo "No routes file found for peer: $peer_ip"
        return 0
    fi
    
    # Check if PPP interface exists for this peer
    local ppp_interface=""
    for iface in /sys/class/net/ppp*; do
        if [[ -d "$iface" ]]; then
            local iface_name=$(basename "$iface")
            # Get the peer IP for this interface
            if ip addr show $iface_name | grep -q "peer $peer_ip"; then
                ppp_interface=$iface_name
                break
            fi
        fi
    done
    
    if [[ -z "$ppp_interface" ]]; then
        echo "Warning: No PPP interface found for peer $peer_ip. Routes will be applied when interface comes up."
        return 0
    fi
    
    # Apply each route
    while IFS= read -r route; do
        if [[ -n "$route" ]]; then
            # Parse route components
            local dst=$(echo "$route" | awk '{print $1}')
            local via=$(echo "$route" | grep -o 'via [0-9.]*' | awk '{print $2}')
            local dev=$(echo "$route" | grep -o 'dev [a-zA-Z0-9]*' | awk '{print $2}')
            
            # Construct ip route command
            local cmd="sudo ip route add $dst"
            if [[ -n "$via" ]]; then
                cmd="$cmd via $via"
            fi
            if [[ -n "$dev" ]]; then
                cmd="$cmd dev $dev"
            else
                cmd="$cmd dev $ppp_interface"
            fi
            
            # Execute command
            echo "Executing: $cmd"
            if eval $cmd; then
                echo "Applied route: $route"
            else
                echo "Failed to apply route: $route"
            fi
        fi
    done < "$routes_file"
}

# Function to apply all routes
apply_all_routes() {
    if [[ -d "$ROUTES_DIR" ]] && [[ -n "$(ls -A $ROUTES_DIR)" ]]; then
        for file in $ROUTES_DIR/*$ROUTES_FILE_EXT; do
            if [[ -f "$file" ]]; then
                local filename=$(basename "$file")
                local peer=$(echo "$filename" | sed "s|$ROUTES_FILE_EXT$||")
                echo "Applying routes for peer: $peer"
                apply_routes $peer
            fi
        done
    else
        echo "No routes to apply"
    fi
}

# Parse command line arguments
if [[ $# -lt 1 ]]; then
    usage
fi

COMMAND=$1
shift

case $COMMAND in
    add)
        PEER=""
        DST=""
        GW=""
        DEV=""
        
        while [[ $# -gt 0 ]]; do
            case $1 in
                --peer)
                    PEER="$2"
                    shift 2
                    ;;
                --dst)
                    DST="$2"
                    shift 2
                    ;;
                --gw)
                    GW="$2"
                    shift 2
                    ;;
                --dev)
                    DEV="$2"
                    shift 2
                    ;;
                *)
                    echo "Unknown option: $1"
                    usage
                    ;;
            esac
        done
        
        if [[ -z "$PEER" ]] || [[ -z "$DST" ]]; then
            echo "Error: --peer and --dst are required for add command"
            usage
        fi
        
        add_route "$PEER" "$DST" "$GW" "$DEV"
        ;;
        
    del)
        PEER=""
        DST=""
        
        while [[ $# -gt 0 ]]; do
            case $1 in
                --peer)
                    PEER="$2"
                    shift 2
                    ;;
                --dst)
                    DST="$2"
                    shift 2
                    ;;
                *)
                    echo "Unknown option: $1"
                    usage
                    ;;
            esac
        done
        
        if [[ -z "$PEER" ]] || [[ -z "$DST" ]]; then
            echo "Error: --peer and --dst are required for del command"
            usage
        fi
        
        del_route "$PEER" "$DST"
        ;;
        
    list)
        PEER=""
        
        while [[ $# -gt 0 ]]; do
            case $1 in
                --peer)
                    PEER="$2"
                    shift 2
                    ;;
                *)
                    echo "Unknown option: $1"
                    usage
                    ;;
            esac
        done
        
        list_routes "$PEER"
        ;;
        
    apply)
        if [[ $# -gt 0 ]]; then
            case $1 in
                --peer)
                    if [[ -z "$2" ]]; then
                        echo "Error: --peer requires an IP address"
                        usage
                    fi
                    apply_routes "$2"
                    ;;
                *)
                    echo "Unknown option: $1"
                    usage
                    ;;
            esac
        else
            apply_all_routes
        fi
        ;;
        
    *)
        echo "Unknown command: $COMMAND"
        usage
        ;;
esac
EOF

# Make the CLI tool executable
sudo chmod +x /usr/local/sbin/l2tp-routectl

# Create ip-up hook
echo -e "${YELLOW}Creating ip-up hook...${NC}"
sudo mkdir -p /etc/ppp/ip-up.d
sudo tee /etc/ppp/ip-up.d/l2tp-routes > /dev/null << 'EOF'
#!/bin/bash

# This script is called when a PPP interface comes up
# It applies any custom routes for the connecting user

# Get the peer IP from environment variables
PEER_IP=$5

if [[ -n "$PEER_IP" ]]; then
    # Apply routes for this peer
    /usr/local/sbin/l2tp-routectl apply --peer $PEER_IP
fi
EOF

# Make the ip-up hook executable
sudo chmod +x /etc/ppp/ip-up.d/l2tp-routes

# Create ip-down hook
echo -e "${YELLOW}Creating ip-down hook...${NC}"
sudo mkdir -p /etc/ppp/ip-down.d
sudo tee /etc/ppp/ip-down.d/l2tp-routes > /dev/null << 'EOF'
#!/bin/bash

# This script is called when a PPP interface goes down
# It removes any custom routes for the disconnecting user

# Get the peer IP from environment variables
PEER_IP=$5

if [[ -n "$PEER_IP" ]]; then
    # Remove all routes via this peer
    # Note: This is a simplified approach - in production, you might want to be more specific
    ip route show | grep "via $PEER_IP" | while read route; do
        route_dst=$(echo $route | awk '{print $1}')
        ip route del $route_dst via $PEER_IP 2>/dev/null || true
    done
fi
EOF

# Make the ip-down hook executable
sudo chmod +x /etc/ppp/ip-down.d/l2tp-routes

# Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
sudo tee /etc/systemd/system/route-l2tp-apply-all.service > /dev/null << 'EOF'
[Unit]
Description=Apply all L2TP per-user routes
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/l2tp-routectl apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Create systemd timer to apply routes periodically (optional)
sudo tee /etc/systemd/system/route-l2tp-apply-all.timer > /dev/null << 'EOF'
[Unit]
Description=Periodically apply all L2TP per-user routes
Requires=route-l2tp-apply-all.service

[Timer]
OnBootSec=15
OnUnitActiveSec=60

[Install]
WantedBy=timers.target
EOF

# Create sysctl configuration
echo -e "${YELLOW}Creating sysctl configuration...${NC}"
sudo tee /etc/sysctl.d/99-l2tp-routing.conf > /dev/null << 'EOF'
# Enable IP forwarding
net.ipv4.ip_forward = 1

# Set rp_filter to loose mode for PPP interfaces
net.ipv4.conf.ppp*.rp_filter = 2
EOF

# Apply sysctl settings
sudo sysctl -p /etc/sysctl.d/99-l2tp-routing.conf

# Create sudoers configuration for www-data
echo -e "${YELLOW}Creating sudoers configuration...${NC}"
sudo tee /etc/sudoers.d/l2tp-routectl > /dev/null << 'EOF'
# Allow www-data to run l2tp-routectl without password
www-data ALL=(ALL) NOPASSWD: /usr/local/sbin/l2tp-routectl
EOF

# Set proper permissions for sudoers file
sudo chmod 440 /etc/sudoers.d/l2tp-routectl

# Enable and start systemd services
echo -e "${YELLOW}Enabling systemd services...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable route-l2tp-apply-all.service
sudo systemctl enable route-l2tp-apply-all.timer

echo -e "${GREEN}L2TP Per-User Routing System installed successfully!${NC}"
echo -e "${YELLOW}To start using it, you can:${NC}"
echo -e "  - Add a route: sudo /usr/local/sbin/l2tp-routectl add --peer 10.255.10.11 --dst 10.255.10.0/24"
echo -e "  - List routes: sudo /usr/local/sbin/l2tp-routectl list"
echo -e "  - Apply routes: sudo /usr/local/sbin/l2tp-routectl apply --peer 10.255.10.11"