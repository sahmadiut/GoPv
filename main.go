package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
	"log"
)

// Configuration constants
const (
	privateScriptPath  = "/usr/local/bin/private"
	privateInstallCmd1 = "wget -O /usr/local/bin/private https://k4m.me/bot/private.sh > /dev/null 2>&1"
	privateInstallCmd2 = "chmod +x /usr/local/bin/private"
	xUIDBPath          = "/etc/x-ui/x-ui.db"
	defaultPort        = "8443"
	updateScriptURL    = "https://k4m.me/bot/gopv.sh"
	updateScriptPath   = "/root/gopv.sh"
	versionInfo        = "0.18"
)

// Global variables
var (
	logger          *log.Logger
	ansiColorRegexp = regexp.MustCompile(`\x1B[@-_][0-?]*[ -/]*[@-~]`)
	ipv4Regex       = regexp.MustCompile(`^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`)
	domainRegex     = regexp.MustCompile(`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`)
)

// Initialize logger
func init() {
	logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Remove ANSI color codes from text
func removeANSICodes(text string) string {
	return ansiColorRegexp.ReplaceAllString(text, "")
}

// Install the private tool
func installPrivate() error {
	logger.Println("Installing private tool...")
	if _, err := runScript(privateInstallCmd1, "", false); err != nil {
		return err
	}
	if _, err := runScript(privateInstallCmd2, "", false); err != nil {
		return err
	}
	logger.Println("Private command installed successfully.")
	return nil
}

// Run a shell command with optional executable and ANSI color code removal
func runScript(command string, executable string, removeColor bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if executable != "" {
		cmd = exec.CommandContext(ctx, executable, "-c", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	output, _ := cmd.CombinedOutput()
	//if err != nil {
	//	return "", fmt.Errorf("%s", removeANSICodes(string(output)))
	//}

	result := string(output)
	if removeColor {
		result = removeANSICodes(result)
	}

	return result, nil
}

// Get certificate files from predefined paths or the database
func getCertificateFiles() (map[string]string, error) {
	certPaths := []struct {
		cert string
		key  string
	}{
		{"/root/all_k4m/cert.crt", "/root/all_k4m/private.key"},
		{"/root/sajjad.engineer/fullchain.pem", "/root/sajjad.engineer/privkey.pem"},
	}

	for _, paths := range certPaths {
		if fileExists(paths.cert) && fileExists(paths.key) {
			return map[string]string{
				"webCertFile": paths.cert,
				"webKeyFile":  paths.key,
			}, nil
		}
	}

	logger.Println("Certificate files not found in predefined paths")

	// Check SQLite database
	if !fileExists(xUIDBPath) {
		return nil, errors.New("certificate files not found and x-ui database does not exist")
	}

	logger.Println("Checking x-ui database for certificate files")

	db, err := sql.Open("sqlite3", xUIDBPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	logger.Println("Database connection established")

	rows, err := db.Query("SELECT `key`, `value` FROM settings WHERE `key` IN ('webCertFile', 'webKeyFile');")
	if err != nil {
		logger.Println(err)
		return nil, err
	}
	defer rows.Close()

	logger.Println("Query executed")

	result := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}

	logger.Println("Result fetched")

	if len(result) == 2 {
		return result, nil
	}

	return nil, errors.New("certificate files not found in the database")
}

// Check if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// Handler for /backhaul
func handleBackhaul(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" {
		respondJSON(w, http.StatusOK, map[string]string{"error": "Missing required action parameter..."})
		return
	}

	backCommand := "bash <(curl -fsSL https://k4m.me/bot/b.sh)"

	switch action {
	case "stop":
		command := fmt.Sprintf("%s stop", backCommand)
		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active backhaul", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "status":
		command := "systemctl status backhaul --no-pager"
		result, err := runScript(command, "", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active backhaul", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "set":
		typ := r.URL.Query().Get("type")
		remoteIP := r.URL.Query().Get("ip")
		version := r.URL.Query().Get("version")
		transport := r.URL.Query().Get("transport")
		pro := r.URL.Query().Get("pro")

		if typ == "" || remoteIP == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required parameters for set action"})
			return
		}

		command := fmt.Sprintf("%s %s %s", backCommand, typ, remoteIP)
		if version != "" {
			command += fmt.Sprintf(" -v %s", version)
		}
		if transport != "" {
			command += fmt.Sprintf(" -t %s", transport)
		}
		if pro == "true" {
			command += fmt.Sprintf(" -x")
		}

		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active backhaul", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
			"command":  command,
		})
	case "log":
		command := fmt.Sprintf("%s log 20", backCommand)
		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active backhaul", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "file":
		path := "/root/config.toml"
		if !fileExists(path) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, path)
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid action"})
	}
}

// Handler for /gost
func handleGost(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" {
		respondJSON(w, http.StatusOK, map[string]string{"error": "Missing required action parameter..."})
		return
	}

	switch action {
	case "stop":
		command := "bash <(curl -fsSL https://sub.freeeiran.me/bot/gost.sh) stop"
		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active gost", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "status":
		command := "systemctl status gost --no-pager"
		result, err := runScript(command, "", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active gost", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "reverse":
		port := r.URL.Query().Get("port")
		domain := r.URL.Query().Get("domain")
		command := "bash <(curl -fsSL https://sub.freeeiran.me/bot/gost.sh) reverse"

		if domain != "" {
			command += fmt.Sprintf(" %s", domain)
		}
		if port != "" {
			command += fmt.Sprintf(" %s", port)
		}

		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active gost", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "log":
		command := "bash <(curl -fsSL https://sub.freeeiran.me/bot/gost.sh) log 20"
		result, err := runScript(command, "/bin/bash", true)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		status, _ := runScript("systemctl is-active gost", "", true)
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
			"status":   strings.TrimSpace(status),
		})
	case "file":
		path := "/etc/gost/gost.yml"
		if !fileExists(path) {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, path)
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid action"})
	}
}

// Handler for /private
func handlePrivate(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action == "" {
		respondJSON(w, http.StatusOK, map[string]string{"error": "Missing required action parameter..."})
		return
	}

	defaultRoles := "server"

	switch action {
	case "set":
		role := r.URL.Query().Get("role")
		if role == "" {
			role = defaultRoles
		}
		remoteIP := r.URL.Query().Get("ip")
		remoteIPv6 := r.URL.Query().Get("ipv6")
		mainIP := r.URL.Query().Get("main_ip")

		if remoteIP == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required parameters for set action"})
			return
		}

		command := fmt.Sprintf("sudo %s set %s %s", privateScriptPath, role, remoteIP)
		if mainIP != "" {
			command += fmt.Sprintf(" %s", mainIP)
		}
		if remoteIPv6 != "" {
			command += fmt.Sprintf(" %s", remoteIPv6)
		}

		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
		})
	case "show":
		command := "sudo /usr/local/bin/private show"
		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		configurations, err := parsePrivateShowOutput(result)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"configurations": configurations,
		})
	case "ping":
		remoteIP := r.URL.Query().Get("ip")
		command := "sudo /usr/local/bin/private ping"
		if remoteIP != "" {
			command += fmt.Sprintf(" %s", remoteIP)
		}
		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
		})
	case "delete":
		clientIP := r.URL.Query().Get("ip")
		if clientIP == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required client_ip parameter"})
			return
		}
		command := fmt.Sprintf("sudo %s delete %s", privateScriptPath, clientIP)
		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
		})
	case "service":
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required ip parameter"})
			return
		}
		command := fmt.Sprintf("sudo %s service %s", privateScriptPath, ip)
		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
		})
	case "log":
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing required ip parameter"})
			return
		}
		command := fmt.Sprintf("sudo %s service %s loge", privateScriptPath, ip)
		result, err := runScript(command, "", false)
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"response": strings.Split(strings.TrimSpace(result), "\n"),
		})
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid action"})
	}
}

// Parse the output of the 'private show' command
func parsePrivateShowOutput(output string) ([]map[string]interface{}, error) {
	blocks := strings.Split(strings.TrimSpace(output), "\n\n")
	var configurations []map[string]interface{}

	for _, block := range blocks {
		lines := strings.Split(block, "\n")
		if len(lines) < 4 {
			continue
		}

		// Initialize configuration map
		config := make(map[string]interface{})

		// Extract the name (from "Configuration file:" line)
		nameLine := strings.TrimSpace(lines[0])
		if strings.HasPrefix(nameLine, "Configuration file: ") {
			config["name"] = strings.TrimPrefix(nameLine, "Configuration file: ")
		} else {
			// If we can't find the correct prefix, we might need additional handling here
			config["name"] = nameLine
		}

		// Extract local and remote info (handle possible malformed fields)
		if len(lines) > 1 {
			localLine := strings.TrimPrefix(lines[1], "Local is: ")
			localParts := strings.Split(localLine, " ")
			if len(localParts) >= 2 {
				config["local"] = localParts[0]
				config["local_role"] = strings.Trim(localParts[1], "()")
			} else {
				// Fallback if parsing fails
				config["local"] = "Unknown"
				config["local_role"] = "Unknown"
			}
		}

		if len(lines) > 2 {
			remoteLine := strings.TrimPrefix(lines[2], "Remote is: ")
			remoteParts := strings.Split(remoteLine, " ")
			if len(remoteParts) >= 2 {
				config["remote"] = remoteParts[0]
				config["remote_role"] = strings.Trim(remoteParts[1], "()")
			} else {
				// Fallback if parsing fails
				config["remote"] = "Unknown"
				config["remote_role"] = "Unknown"
			}
		}

		if len(lines) > 3 {
			config["remote_ipv6"] = strings.Split(strings.TrimPrefix(lines[3], "Remote IPv6: "), " ")[0]
		} else {
			config["remote_ipv6"] = "Unknown"
		}

		// Handle GRE IPv6 fields with proper checks
		if len(lines) > 4 {
			config["remote_ipv6_gre"] = strings.TrimPrefix(lines[4], "Remote IPv6 GRE: ")
		} else {
			config["remote_ipv6_gre"] = "N/A"
		}

		// Fetch logs using the script
		commandLog := fmt.Sprintf("sudo %s service %s loge", privateScriptPath, config["remote"])
		logOutput, err := runScript(commandLog, "", false)
		if err != nil {
			config["log"] = []string{"Failed to retrieve logs"}
		} else {
			logLines := strings.Split(strings.TrimSpace(logOutput), "\n")
			if len(logLines) >= 4 {
				config["log"] = logLines[len(logLines)-4:]
			} else {
				config["log"] = logLines
			}
		}

		// Append the configuration to the result list
		configurations = append(configurations, config)
	}

	return configurations, nil
}

// Handler for root '/'
func handleXray(w http.ResponseWriter, r *http.Request) {
	command := "ps -ef | grep -E '(bin/xray|/var/lib/marzban/xray-core/xray)' | grep -v 'grep' | wc -l"
	result, err := runScript(command, "", true)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	command2 := "hostname -I | awk '{print $1}'"
	result2, err := runScript(command2, "", false)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	ipv4 := strings.TrimSpace(result2)

	count := strings.TrimSpace(result)
	logger.Printf("Xray status: %s\n", count)
	status := "stopped"
	if countInt, err := strconv.Atoi(count); err == nil && countInt > 0 {
		status = "running"
	}

	respondJSON(w, http.StatusOK, map[string]string{"xray_status": status, "ipv4": ipv4})
}

// Handler for /update
func handleUpdate(w http.ResponseWriter, r *http.Request) {
	command1 := fmt.Sprintf("wget -O %s %s > /dev/null 2>&1", updateScriptPath, updateScriptURL)
	if _, err := runScript(command1, "", false); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	command2 := fmt.Sprintf("chmod +x %s", updateScriptPath)
	if _, err := runScript(command2, "", false); err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	command3 := fmt.Sprintf("%s -f > /dev/null 2>&1", updateScriptPath)
	go func() {
		if _, err := runScript(command3, "", false); err != nil {
			logger.Printf("Update script error: %v\n", err)
		}
	}()

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Handler for /version
func handleVersion(w http.ResponseWriter, r *http.Request) {
	logger.Println("Version " + versionInfo)
	respondJSON(w, http.StatusOK, map[string]string{"version": versionInfo})
}

// Validate IPv4 address
func isValidIP(ip string) bool {
	return ipv4Regex.MatchString(ip)
}

// Run ping command
func runPing(ip string, count, timeout int) (string, error) {
	command := fmt.Sprintf("ping -c %d -W %d %s", count, timeout, ip)
	return runScript(command, "", false)
}

// Parse ping output
func parsePingOutput(output string) ([]float64, *float64, error) {
	var times []float64
	var avg *float64

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "time=") {
			parts := strings.Split(line, "time=")
			if len(parts) < 2 {
				continue
			}
			timePart := strings.Split(parts[1], " ")[0]
			timeVal, err := strconv.ParseFloat(timePart, 64)
			if err != nil {
				continue
			}
			times = append(times, timeVal)
		}
	}

	if len(times) > 0 {
		sum := 0.0
		for _, t := range times {
			sum += t
		}
		average := sum / float64(len(times))
		avg = &average
	}

	return times, avg, nil
}

// Handler for /ping
func handlePing(w http.ResponseWriter, r *http.Request) {
	logger.Println("Ping request received")
	ip := r.URL.Query().Get("ip")
	if ip == "" || !isValidIP(ip) {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or missing required ip parameter"})
		return
	}

	countStr := r.URL.Query().Get("count")
	timeoutStr := r.URL.Query().Get("timeout")

	count := 4
	timeout := 5
	var err error

	if countStr != "" {
		count, err = strconv.Atoi(countStr)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Count must be an integer"})
			return
		}
	}

	if timeoutStr != "" {
		timeout, err = strconv.Atoi(timeoutStr)
		if err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Timeout must be an integer"})
			return
		}
	}

	result, err := runPing(ip, count, timeout)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	responseTimes, avgTime, err := parsePingOutput(result)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to parse ping output"})
		return
	}

	rawResponse := strings.Split(strings.TrimSpace(result), "\n")
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"ip":                    ip,
		"ping_count":            count,
		"timeout":               timeout,
		"response_times_ms":     responseTimes,
		"average_response_time": avgTime,
		"raw_response":          rawResponse,
	})
}

// Handler for /warp
func handleWarp(w http.ResponseWriter, r *http.Request) {
	logger.Println("Warp request received")
	action := r.URL.Query().Get("action")
	endResult := make(map[string]interface{})

	command := "curl -x socks5h://127.0.0.1:40000 https://bot.sajjad.engineer/bot/myip.php -4 -s"
	result, err := runScript(command, "", false)
	if err != nil {
		endResult["warp_ip"] = "Error retrieving IP"
	} else {
		endResult["warp_ip"] = strings.TrimSpace(result)
	}

	logger.Printf("Warp status: %s\n", endResult["warp_ip"])

	if action == "" {
		respondJSON(w, http.StatusOK, endResult)
		return
	}

	if !fileExists(xUIDBPath) {
		endResult["ok"] = false
		endResult["response"] = "Not supported"
		respondJSON(w, http.StatusOK, endResult)
		return
	}

	db, err := sql.Open("sqlite3", xUIDBPath)
	if err != nil {
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Database connection failed"})
		return
	}
	defer db.Close()

	switch action {
	case "config":
		var configJSON string
		err := db.QueryRow("SELECT value FROM settings WHERE `key` = 'xrayTemplateConfig'").Scan(&configJSON)
		if err != nil {
			endResult["ok"] = false
			endResult["response"] = "Xray configuration is not found"
			respondJSON(w, http.StatusOK, endResult)
			return
		}

		var xrayConfig map[string]interface{}
		if err := json.Unmarshal([]byte(configJSON), &xrayConfig); err != nil {
			endResult["ok"] = false
			endResult["response"] = "Failed to parse Xray configuration"
			respondJSON(w, http.StatusOK, endResult)
			return
		}

		// Check if WARP outbound is configured
		warpOutboundFound := false
		if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
			for _, outbound := range outbounds {
				if outboundMap, ok := outbound.(map[string]interface{}); ok {
					if outboundMap["tag"] == "WARP" {
						warpOutboundFound = true
						break
					}
				}
			}
		}

		if !warpOutboundFound {
			endResult["ok"] = false
			endResult["response"] = "WARP is not installed in xray outbounds"
			respondJSON(w, http.StatusOK, endResult)
			return
		}

		// Extract routing rules
		warpRoutingFound := false
		var warpConfig map[string]interface{}
		if routing, ok := xrayConfig["routing"].(map[string]interface{}); ok {
			if rules, ok := routing["rules"].([]interface{}); ok {
				for _, rule := range rules {
					if ruleMap, ok := rule.(map[string]interface{}); ok {
						if ruleMap["outboundTag"] == "WARP" {
							warpRoutingFound = true
							warpConfig = ruleMap
							break
						}
					}
				}
			}
		}

		endResult["ok"] = true
		if warpRoutingFound {
			endResult["config"] = warpConfig
		} else {
			endResult["config"] = map[string]interface{}{"domain": []interface{}{}}
		}

		respondJSON(w, http.StatusOK, endResult)
	case "set":
		logger.Println("Warp set action")
		domains := r.URL.Query().Get("domains")
		mode := r.URL.Query().Get("mode")

		logger.Printf("Domains: %s\n", domains)

		var configJSON string
		err := db.QueryRow("SELECT value FROM settings WHERE `key` = 'xrayTemplateConfig'").Scan(&configJSON)
		if err != nil {
			// Load default config
			defaultConfigPath := "/root/default_xray_config.json"
			defaultConfigURL := "https://k4m.me/bot/default_xray_config.json"
			downloadCmd := fmt.Sprintf("wget -O %s %s > /dev/null 2>&1", defaultConfigPath, defaultConfigURL)
			if _, err := runScript(downloadCmd, "", false); err != nil {
				endResult["ok"] = false
				endResult["response"] = "Failed to download default Xray configuration"
				respondJSON(w, http.StatusInternalServerError, endResult)
				return
			}

			configData, err := ioutil.ReadFile(defaultConfigPath)
			if err != nil {
				endResult["ok"] = false
				endResult["response"] = "Failed to read default Xray configuration"
				respondJSON(w, http.StatusInternalServerError, endResult)
				return
			}

			configJSON = string(configData)
		}

		var xrayConfig map[string]interface{}
		if err := json.Unmarshal([]byte(configJSON), &xrayConfig); err != nil {
			endResult["ok"] = false
			endResult["response"] = "Failed to parse Xray configuration"
			respondJSON(w, http.StatusInternalServerError, endResult)
			return
		}

		// Ensure WARP outbound exists
		warpOutbound := map[string]interface{}{
			"tag":      "WARP",
			"protocol": "socks",
			"settings": map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{
						"address": "127.0.0.1",
						"port":    40000,
					},
				},
			},
		}

		warpOutboundFound := false
		if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
			for _, outbound := range outbounds {
				if outboundMap, ok := outbound.(map[string]interface{}); ok {
					if outboundMap["tag"] == "WARP" {
						warpOutboundFound = true
						break
					}
				}
			}
		}

		if !warpOutboundFound {
			if outbounds, ok := xrayConfig["outbounds"].([]interface{}); ok {
				xrayConfig["outbounds"] = append(outbounds, warpOutbound)
			} else {
				xrayConfig["outbounds"] = []interface{}{warpOutbound}
			}
		}

		// Process domains
		var newDomains []string
		if domains != "" {
			domainList := strings.Split(domains, ",")
			for _, domain := range domainList {
				domain = strings.TrimSpace(domain)
				if strings.HasPrefix(domain, "domain:") || strings.HasPrefix(domain, "geosite:") {
					newDomains = append(newDomains, domain)
				} else if domainRegex.MatchString(domain) {
					newDomains = append(newDomains, fmt.Sprintf("domain:%s", domain))
				} else {
					newDomains = append(newDomains, fmt.Sprintf("geosite:%s", domain))
				}
			}
		}

		if domains != "" {
			warpRoutingFound := false
			var warpConfig map[string]interface{}
			if routing, ok := xrayConfig["routing"].(map[string]interface{}); ok {
				if rules, ok := routing["rules"].([]interface{}); ok {
					for _, rule := range rules {
						if ruleMap, ok := rule.(map[string]interface{}); ok {
							if ruleMap["outboundTag"] == "WARP" {
								warpRoutingFound = true
								warpConfig = ruleMap
								break
							}
						}
					}
				}
			}

			if !warpRoutingFound {
				warpConfig = map[string]interface{}{
					"type":        "field",
					"outboundTag": "WARP",
					"domain":      []interface{}{},
				}
				if routing, ok := xrayConfig["routing"].(map[string]interface{}); ok {
					if rules, ok := routing["rules"].([]interface{}); ok {
						xrayConfig["routing"].(map[string]interface{})["rules"] = append(rules, warpConfig)
					} else {
						xrayConfig["routing"].(map[string]interface{})["rules"] = []interface{}{warpConfig}
					}
				}
			}

			currentDomains, _ := warpConfig["domain"].([]interface{})
			domainSet := make(map[string]struct{})
			for _, d := range currentDomains {
				if ds, ok := d.(string); ok {
					domainSet[ds] = struct{}{}
				}
			}

			switch mode {
			case "add":
				for _, d := range newDomains {
					domainSet[d] = struct{}{}
				}
			case "remove":
				for _, d := range newDomains {
					delete(domainSet, d)
				}
			case "set":
				domainSet = make(map[string]struct{})
				for _, d := range newDomains {
					domainSet[d] = struct{}{}
				}
			default:
				respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid mode"})
				return
			}

			// Convert set back to slice
			finalDomains := []interface{}{}
			for d := range domainSet {
				finalDomains = append(finalDomains, d)
			}
			warpConfig["domain"] = finalDomains
		}

		// Remove WARP routing if domain list is empty
		if routing, ok := xrayConfig["routing"].(map[string]interface{}); ok {
			if rules, ok := routing["rules"].([]interface{}); ok {
				newRules := []interface{}{}
				for _, rule := range rules {
					if ruleMap, ok := rule.(map[string]interface{}); ok {
						if ruleMap["outboundTag"] == "WARP" {
							if domains == "" {
								continue
							}
						}
					}
					newRules = append(newRules, rule)
				}
				routing["rules"] = newRules
			}
		}

		// Update the database
		updatedConfig, err := json.MarshalIndent(xrayConfig, "", "  ")
		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to marshal Xray configuration"})
			return
		}

		var insert bool
		var existing string
		err = db.QueryRow("SELECT value FROM settings WHERE `key` = 'xrayTemplateConfig'").Scan(&existing)
		if err != nil {
			insert = true
		}

		if insert {
			_, err = db.Exec("INSERT INTO settings (key, value) VALUES (?, ?)", "xrayTemplateConfig", string(updatedConfig))
		} else {
			_, err = db.Exec("UPDATE settings SET value = ? WHERE `key` = 'xrayTemplateConfig'", string(updatedConfig))
		}

		if err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update Xray configuration"})
			return
		}

		// Restart x-ui
		if _, err := runScript("x-ui restart", "", false); err != nil {
			respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to restart x-ui"})
			return
		}

		endResult["ok"] = true
		endResult["response"] = "WARP configuration updated successfully"
		respondJSON(w, http.StatusOK, endResult)
	default:
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid action"})
	}
}

// Handler for /warp (additional functionalities)
func handleWarpSetConfig(w http.ResponseWriter, r *http.Request) {
	// This function can be implemented based on specific requirements
}

// Helper function to respond with JSON
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	response, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		logger.Printf("JSON marshal error: %v\n", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
}

func generate204(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log request method, URL, and any other relevant info
		logger.Printf("%s %s   |   %s\n", r.Method, r.URL.String(), r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func getPort() string {
	// Check for port in command line arguments
	if len(os.Args) > 2 && os.Args[1] == "-p" {
		return os.Args[2] // Get port from argument like: -p 8080
	}

	// Check for port in environment variable
	port := os.Getenv("GOPV_PORT")
	if port != "" {
		return port // Use the environment variable PORT if set
	}

	// Fallback to default port
	return defaultPort
}

// Main function
func main() {
	// Check for version flag
	if len(os.Args) > 1 && os.Args[1] == "-v" {
		fmt.Println(versionInfo)
		return
	}

	// Install private tool
	if err := installPrivate(); err != nil {
		logger.Fatalf("Failed to install private tool: %v\n", err)
	}

	// Get certificate files
	certFiles, err := getCertificateFiles()
	if err != nil {
		logger.Println("Certificate files not found, running server without SSL.")
	} else {
		logger.Printf("Certificate files: %+v\n", certFiles)
	}

	// Set up router
	router := mux.NewRouter()

	router.Use(loggingMiddleware)

	// Define routes
	router.HandleFunc("/backhaul", handleBackhaul).Methods("GET")
	router.HandleFunc("/gost", handleGost).Methods("GET")
	router.HandleFunc("/private", handlePrivate).Methods("GET")
	router.HandleFunc("/", handleXray).Methods("GET")
	router.HandleFunc("/update", handleUpdate).Methods("GET")
	router.HandleFunc("/version", handleVersion).Methods("GET")
	router.HandleFunc("/ping", handlePing).Methods("GET")
	router.HandleFunc("/warp", handleWarp).Methods("GET")
	router.HandleFunc("/stats", statsHandler).Methods("GET")
	// generate_204
	router.HandleFunc("/generate_204", generate204).Methods("GET")

	// Set up CORS
	corsHandler := cors.Default().Handler(router)

	port := getPort()

	// Server configuration
	server := &http.Server{
		Handler:      corsHandler,
		Addr:         "[::]:" + port,
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
	}

	// Start server with SSL if certs are available
	if certFiles != nil {
		go func() {
			for {
				logger.Println("Starting the server with SSL...")
				logger.Println("addr: ", server.Addr)
				err := server.ListenAndServeTLS(certFiles["webCertFile"], certFiles["webKeyFile"])
				if err != nil {
					logger.Printf("Error starting server with SSL: %v\n", err)
					time.Sleep(5 * time.Second)
				}
			}
		}()
	} else {
		go func() {
			for {
				logger.Println("Starting the server without SSL...")
				logger.Println("addr: ", server.Addr)
				err := server.ListenAndServe()
				if err != nil {
					logger.Printf("Error starting server: %v\n", err)
					time.Sleep(5 * time.Second)
				}
			}
		}()
	}

	// Block main goroutine
	select {}
}
