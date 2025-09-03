# Create the l2tp-routectl CLI tool
echo -e "${YELLOW}Creating l2tp-routectl CLI tool...${NC}"
sudo tee /usr/local/sbin/l2tp-routectl > /dev/null << 'EOF'
#!/bin/bash

# l2tp-routectl - CLI tool for managing per-user routes
# Usage: l2tp-routectl [command] [options]

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
        return 1
    fi
    
    if ! validate_cidr $dst_cidr; then
        echo "Error: Invalid destination CIDR: $dst_cidr"
        return 1
    fi
    
    if [[ -n "$gateway" ]] && ! validate_ip $gateway; then
        echo "Error: Invalid gateway IP address: $gateway"
        return 1
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
    return 0
}

# Function to delete a route
del_route() {
    local peer_ip=$1
    local dst_cidr=$2
    
    # Validate inputs
    if ! validate_ip $peer_ip; then
        echo "Error: Invalid peer IP address: $peer_ip"
        return 1
    fi
    
    # Check if we're deleting all routes for this peer
    if [[ "$dst_cidr" == "all" ]]; then
        local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
        
        if [[ ! -f "$routes_file" ]]; then
            echo "No routes file found for peer: $peer_ip"
            return 0
        fi
        
        # Try to delete all routes from the actual routing table
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
        
        if [[ -n "$ppp_interface" ]]; then
            # Delete each route from the routing table
            while IFS= read -r route; do
                if [[ -n "$route" ]]; then
                    local dst=$(echo "$route" | awk '{print $1}')
                    # Construct ip route delete command
                    local cmd="ip route del $dst dev $ppp_interface"
                    echo "Executing: $cmd"
                    if eval $cmd 2>/dev/null; then
                        echo "Deleted route from routing table: $dst"
                    else
                        # Try without dev parameter if it fails
                        cmd="ip route del $dst"
                        if eval $cmd 2>/dev/null; then
                            echo "Deleted route from routing table: $dst"
                        else
                            echo "Warning: Failed to delete route from routing table: $dst"
                        fi
                    fi
                fi
            done < "$routes_file"
        else
            echo "Warning: No PPP interface found for peer $peer_ip. Routes may still exist in routing table."
        fi
        
        # Remove the entire routes file
        sudo rm -f "$routes_file"
        echo "Removed all routes for peer: $peer_ip"
        return 0
    fi
    
    # Validate CIDR for single route deletion
    if ! validate_cidr $dst_cidr; then
        echo "Error: Invalid destination CIDR: $dst_cidr"
        return 1
    fi
    
    local routes_file="$ROUTES_DIR/$peer_ip$ROUTES_FILE_EXT"
    
    if [[ ! -f "$routes_file" ]]; then
        echo "No routes file found for peer: $peer_ip"
        return 0
    fi
    
    # Find the full route entry to get gateway and device information
    local route_entry=$(grep "^$dst_cidr" "$routes_file" | head -n 1)
    
    if [[ -z "$route_entry" ]]; then
        echo "No route found with destination: $dst_cidr"
        return 0
    fi
    
    # Extract gateway and device from the route entry
    local gateway=$(echo "$route_entry" | grep -o 'via [0-9.]*' | awk '{print $2}')
    local device=$(echo "$route_entry" | grep -o 'dev [a-zA-Z0-9]*' | awk '{print $2}')
    
    # Set default gateway to peer IP if not provided in route entry
    if [[ -z "$gateway" ]]; then
        gateway=$peer_ip
    fi
    
    # Try to delete from the actual routing table
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
    
    if [[ -n "$ppp_interface" ]]; then
        # Construct ip route delete command
        local cmd="ip route del $dst_cidr"
        if [[ -n "$device" ]]; then
            cmd="$cmd dev $device"
        else
            cmd="$cmd dev $ppp_interface"
        fi
        
        # Execute command to delete from routing table
        echo "Executing: $cmd"
        if eval $cmd 2>/dev/null; then
            echo "Deleted route from routing table: $dst_cidr"
        else
            # Try without dev parameter if it fails
            if [[ -z "$device" ]]; then
                cmd="ip route del $dst_cidr"
                if eval $cmd 2>/dev/null; then
                    echo "Deleted route from routing table: $dst_cidr"
                else
                    echo "Warning: Failed to delete route from routing table: $dst_cidr"
                fi
            else
                echo "Warning: Failed to delete route from routing table: $dst_cidr"
            fi
        fi
    else
        echo "Warning: No PPP interface found for peer $peer_ip. Route may still exist in routing table."
    fi
    
    # Remove route from file
    sudo sed -i "\|^$dst_cidr|d" "$routes_file"
    echo "Deleted route with destination: $dst_cidr"
    
    # Remove file if empty
    if [[ ! -s "$routes_file" ]]; then
        sudo rm -f "$routes_file"
        echo "Removed empty routes file for peer: $peer_ip"
    fi
    return 0
}

# Function to list routes
list_routes() {
    local peer_ip=$1
    
    if [[ -n "$peer_ip" ]]; then
        # List routes for specific peer
        if ! validate_ip $peer_ip; then
            echo "Error: Invalid peer IP address: $peer_ip"
            return 1
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
    return 0
}

# Function to apply routes for a peer
apply_routes() {
    local peer_ip=$1
    
    # Validate input
    if ! validate_ip $peer_ip; then
        echo "Error: Invalid peer IP address: $peer_ip"
        return 1
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
    
    local success_count=0
    local fail_count=0
    
    # Apply each route
    while IFS= read -r route; do
        if [[ -n "$route" ]]; then
            # Parse route components
            local dst=$(echo "$route" | awk '{print $1}')
            local via=$(echo "$route" | grep -o 'via [0-9.]*' | awk '{print $2}')
            local dev=$(echo "$route" | grep -o 'dev [a-zA-Z0-9]*' | awk '{print $2}')
            
            # Construct ip route command
            local cmd="ip route add $dst"
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
            if eval $cmd 2>/dev/null; then
                echo "Applied route: $route"
                ((success_count++))
            else
                # Try without dev parameter if it fails
                if [[ -z "$dev" ]]; then
                    cmd="ip route add $dst via $via"
                    if eval $cmd 2>/dev/null; then
                        echo "Applied route: $route"
                        ((success_count++))
                    else
                        echo "Failed to apply route: $route"
                        ((fail_count++))
                    fi
                else
                    echo "Failed to apply route: $route"
                    ((fail_count++))
                fi
            fi
        fi
    done < "$routes_file"
    
    echo "Route application complete. Success: $success_count, Failed: $fail_count"
    return 0
}

# Function to apply all routes
apply_all_routes() {
    local total_success=0
    local total_fail=0
    
    if [[ -d "$ROUTES_DIR" ]] && [[ -n "$(ls -A $ROUTES_DIR)" ]]; then
        for file in $ROUTES_DIR/*$ROUTES_FILE_EXT; do
            if [[ -f "$file" ]]; then
                local filename=$(basename "$file")
                local peer=$(echo "$filename" | sed "s|$ROUTES_FILE_EXT$||")
                echo "Applying routes for peer: $peer"
                apply_routes $peer
                echo ""
            fi
        done
    else
        echo "No routes to apply"
    fi
    return 0
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