#!/bin/bash

# Mock backhaul script to reproduce the formatting issue described in the problem statement

# Function to list backhaul instances with formatting issues (current bad implementation)
list_backhaul_instances() {
    echo "Active backhaul instances:"
    echo "Service Name | Status | Target IP | Config File"
    echo "----------------------------------------"
    
    # Simulating the bad output format described in the problem statement
    echo -n "backhaul_185_226_116_57 | "
    systemctl is-active backhaul_185_226_116_57 2>/dev/null || echo "inactive"
    systemctl is-active backhaul_185_226_116_57 2>/dev/null || echo "inactive"
    echo " | 185.226.116.57 | /root/config_185_226_116_57.toml"
    
    echo -n "backhaul_188_121_117_77 | "
    systemctl is-active backhaul_188_121_117_77 2>/dev/null || echo "inactive"
    systemctl is-active backhaul_188_121_117_77 2>/dev/null || echo "inactive"
    echo " | 188.121.117.77 | /root/config_188_121_117_77.toml"
    
    echo -n "backhaul_2_144_6_171 | "
    systemctl is-active backhaul_2_144_6_171 2>/dev/null || echo "active"
    systemctl is-active backhaul_2_144_6_171 2>/dev/null || echo "active"
    echo " | 2.144.6.171 | /root/config_2_144_6_171.toml"
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