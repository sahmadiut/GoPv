#!/bin/bash

# Mock backhaul script to reproduce the formatting issue described in the problem statement

# Function to list backhaul instances with proper formatting
# Fixed issues:
# 1. Removed duplicate status output
# 2. Properly aligned columns using printf
# 3. Show all instances (both active and inactive) with proper formatting  
# 4. Use consistent column widths for better readability
list_backhaul_instances() {
    echo "Active backhaul instances:"
    # Use printf for proper column alignment with consistent widths
    printf "%-27s | %-8s | %-15s | %s\n" "Service Name" "Status" "Target IP" "Config File"
    echo "--------------------------------------------------------------------"
    
    # List of services to check (both active and inactive)
    services=(
        "backhaul_185_226_116_57:185.226.116.57"
        "backhaul_188_121_117_77:188.121.117.77"
        "backhaul_2_144_6_171:2.144.6.171"
    )
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r service_name target_ip <<< "$service_info"
        config_file="/root/config_${target_ip//./_}.toml"
        
        # Get the actual status of the service (only once, no duplicates)
        if [[ "$service_name" == "backhaul_2_144_6_171" ]]; then
            # Simulate this service being active for demo purposes
            status="active"
        elif systemctl is-active "$service_name" >/dev/null 2>&1; then
            status="active"
        else
            status="inactive"
        fi
        
        # Format output with consistent column widths using printf
        printf "%-27s | %-8s | %-15s | %s\n" "$service_name" "$status" "$target_ip" "$config_file"
    done
}

# Main script logic
case "$1" in
    "csv")
        # CSV output for the Go application
        echo "Service Name,Status,Target IP,Config File,Log File"
        echo "backhaul_185_226_116_57,inactive,185.226.116.57,/root/config_185_226_116_57.toml,/var/log/backhaul_185_226_116_57.log"
        echo "backhaul_188_121_117_77,inactive,188.121.117.77,/root/config_188_121_117_77.toml,/var/log/backhaul_188_121_117_77.log"
        echo "backhaul_2_144_6_171,active,2.144.6.171,/root/config_2_144_6_171.toml,/var/log/backhaul_2_144_6_171.log"
        ;;
    "list")
        list_backhaul_instances
        ;;
    "start"|"stop"|"restart"|"status"|"log")
        echo "Action $1 executed"
        ;;
    *)
        echo "Usage: $0 {csv|list|start|stop|restart|status|log}"
        exit 1
        ;;
esac