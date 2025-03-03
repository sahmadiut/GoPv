package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

type SystemStats struct {
	CPUUsage       string `json:"cpuUsage"`
	CPUCores       int    `json:"cpuCores"`
	RAMUsage       string `json:"ramUsage"`
	RAMTotal       string `json:"ramTotal"`
	DiskUsage      string `json:"diskUsage"`
	SwapUsage      string `json:"swapUsage"`
	SwapTotal      string `json:"swapTotal"`
	NetworkTraffic string `json:"networkTraffic"`
	UploadSpeed    string `json:"uploadSpeed"`
	DownloadSpeed  string `json:"downloadSpeed"`
	AllConnections string `json:"allConnections"`
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats, err := getSystemStats()
	if err != nil {
		logger.Printf("Error fetching system stats: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		logger.Printf("Error encoding JSON: %v", err)
	}
}

// ConvertBytesToReadable converts bytes into a human-readable format (KB, MB, GB)
func convertBytesToReadable(bytes uint64) string {
	const (
		KB = 1 << (10 * 1) // 1024 bytes
		MB = 1 << (10 * 2) // 1024 KB
		GB = 1 << (10 * 3) // 1024 MB
		TB = 1 << (10 * 4) // 1024 TB
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes) // Bytes
	}
}

func getSystemStats() (*SystemStats, error) {

	// Get initial network stats
	initialStats, err := getNetworkStats()
	if err != nil {
		return nil, err
	}

	// Wait for 1 second
	time.Sleep(1 * time.Second)

	// Get updated network stats
	finalStats, err := getNetworkStats()
	if err != nil {
		return nil, err
	}

	// Get CPU usage and count cores
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return nil, err
	}

	// Get CPU cores count
	cpuCores, err := cpu.Counts(true)
	if err != nil {
		return nil, err
	}

	// Get RAM usage
	memStats, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Get Disk usage
	diskStats, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	// Get Swap usage
	swapStats, err := mem.SwapMemory()
	if err != nil {
		return nil, err
	}

	// Get Network traffic
	netStats, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}

	// Get all active network connections (TCP, UDP, etc.)
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	// Calculate upload and download speeds
	uploadSpeed := float64(finalStats.BytesSent - initialStats.BytesSent)
	downloadSpeed := float64(finalStats.BytesRecv - initialStats.BytesRecv)

	stats := &SystemStats{
		CPUUsage:       formatFloat(cpuPercent[0]),
		CPUCores:       cpuCores,
		RAMUsage:       convertBytesToReadable(memStats.Used),
		RAMTotal:       convertBytesToReadable(memStats.Total),
		DiskUsage:      convertBytesToReadable(diskStats.Used),
		SwapUsage:      convertBytesToReadable(swapStats.Used),
		SwapTotal:      convertBytesToReadable(swapStats.Total),
		NetworkTraffic: convertBytesToReadable(netStats[0].BytesSent + netStats[0].BytesRecv),
		DownloadSpeed:  formatSpeed(downloadSpeed),
		UploadSpeed:    formatSpeed(uploadSpeed),
		AllConnections: fmt.Sprintf("%d", len(connections)),
	}

	return stats, nil
}

func formatSpeed(bytesPerSec float64) string {
	if bytesPerSec >= 1e9 {
		return fmt.Sprintf("%.2f GB/s", bytesPerSec/1e9)
	} else if bytesPerSec >= 1e6 {
		return fmt.Sprintf("%.2f MB/s", bytesPerSec/1e6)
	} else if bytesPerSec >= 1e3 {
		return fmt.Sprintf("%.2f KB/s", bytesPerSec/1e3)
	}
	return fmt.Sprintf("%.2f B/s", bytesPerSec)
}

func formatFloat(value float64) string {
	return fmt.Sprintf("%.2f%%", value)
}

func getNetworkStats() (*net.IOCountersStat, error) {
	ioCounters, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}
	if len(ioCounters) == 0 {
		return nil, fmt.Errorf("no network IO counters found")
	}
	return &ioCounters[0], nil
}
