package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"net"
	"time"
	"os/signal"
	"context"
)

func main() {
	// Parse command line flags for ML
	var mlEnabled bool
	var mlURL string
	var mlThreshold float64
	flag.BoolVar(&mlEnabled, "ml", false, "Enable ML integration")
	flag.StringVar(&mlURL, "ml-url", "http://localhost:5000", "ML service URL")
	flag.Float64Var(&mlThreshold, "ml-threshold", 0.8, "ML confidence threshold for auto-block")
	flag.Parse()

	fmt.Println("🛡️  Go Network Firewall - Real-Time Detection Mode (5-Class ML)")
	fmt.Println("==============================================================")

	// Create enhanced firewall instance
	fw := NewFirewall()

	// Initialize ML client if enabled
	if mlEnabled {
		fw.mlClient = NewMLClient(mlURL)
		fw.mlEnabled = true
		fw.mlThreshold = mlThreshold

		fmt.Print("🔍 Checking ML service... ")
		if fw.mlClient.IsServiceAvailable() {
			fmt.Println("✅ Connected!")

			// Get model info to show which is best
			if modelInfo, err := fw.mlClient.GetModelInfo(); err == nil {
				   // ADD THESE DEBUG LINES
				// fmt.Printf("   🔍 DEBUG - Raw model info: %+v\n", modelInfo)
				// fmt.Printf("   🔍 DEBUG - BestModel: %s\n", modelInfo.BestModel)
				// fmt.Printf("   🔍 DEBUG - BestModelF1: %f\n", modelInfo.BestModelF1)

				fmt.Printf("   📊 Best model: %s (F1 Score: %.1f%%)\n",
					modelInfo.BestModel,
					modelInfo.BestModelF1*100)  // Changed to BestModelF1
				fmt.Printf("   📈 Total models: %d\n", len(modelInfo.Models))
				fmt.Printf("   🔢 Features: %d\n", modelInfo.FeaturesCount)
			} else {
				fmt.Printf("   ⚠️ Could not get model info: %v\n", err)
			}

			// Test the multiclass endpoint
			fmt.Println("   🔬 Testing 5-class endpoint...")
			testFeatures := map[string]interface{}{
				"duration": 0.0, "protocol_type": 6, "service": 0, "flag": 0,
				"src_bytes": 100, "dst_bytes": 0, "land": 0, "wrong_fragment": 0,
				"urgent": 0, "hot": 0, "num_failed_logins": 0, "logged_in": 1,
				"num_compromised": 0, "root_shell": 0, "su_attempted": 0,
				"num_root": 0, "num_file_creations": 0, "num_shells": 0,
				"num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0,
				"is_guest_login": 0, "count": 1, "srv_count": 1, "serror_rate": 0.0,
				"srv_serror_rate": 0.0, "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
				"same_srv_rate": 1.0, "diff_srv_rate": 0.0, "srv_diff_host_rate": 0.0,
				"dst_host_count": 1, "dst_host_srv_count": 1,
				"dst_host_same_srv_rate": 1.0, "dst_host_diff_srv_rate": 0.0,
				"dst_host_same_src_port_rate": 1.0, "dst_host_srv_diff_host_rate": 0.0,
				"dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
				"dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
			}

			if multiScore, err := fw.mlClient.MultiClassScore(testFeatures); err == nil {
				fmt.Printf("   ✅ 5-class test: %s (%.1f%% confidence)\n",
					multiScore.PredictedClass, multiScore.Confidence*100)
			} else {
				fmt.Printf("   ⚠️ 5-class test warning: %v\n", err)
			}

			fmt.Printf("   🤖 Auto-block threshold: %.0f%%\n", mlThreshold*100)
		} else {
			fmt.Println("❌ Not available!")
			fmt.Println("   ⚠️ ML features disabled. Make sure ML service is running:")
			fmt.Println("   cd ../ml_pipeline && python ml_service.py")
			fw.mlEnabled = false
		}
	}

	// Add enhanced default rules with priorities
	fw.AddRuleWithPriority("block", "10.0.0.0/8", "any", "any", "Block internal network range", 0, 10)
	fw.AddRuleWithPriority("allow", "192.168.1.100", "any", "any", "Allow specific IP", 0, 20)
	fw.AddRuleWithPriority("block", "any", "any", "tcp", "Block SSH port", 22, 5)
	fw.AddRuleWithPriority("block", "any", "any", "udp", "Block UDP floods", 0, 3)
	fw.AddRuleWithPriority("block", "192.168.1.0/24", "any", "any", "Block suspicious subnet", 0, 8)

	fmt.Println("✅ Enhanced firewall started with DDoS protection and 5-class ML")
	fmt.Println("🔍 Starting real-time network monitoring...")

	// Interface selection
	fmt.Println("🚀 Starting Real-Time Packet Monitor with Firewall Integration")
	fmt.Println("📡 Looking for network interfaces...")

	devices, err := GetNetworkInterfaces()
	if err != nil {
		fmt.Printf("❌ Error finding network interfaces: %v\n", err)
		return
	}

	DisplayInterfaceList(devices)

	fmt.Println("\n📋 Please select a network interface to monitor:")
	selectedInterface := SelectInterface(devices)

	displayName := GetInterfaceDisplayNameByDevice(devices, selectedInterface)
	fmt.Printf(" Starting real-time monitoring on %s\n", displayName)
	fmt.Println(" Firewall is now analyzing LIVE network traffic with 5-class ML!")
	fmt.Println(" This is DETECTION MODE - No actual blocking, just monitoring")
	fmt.Println(strings.Repeat("─", 80))

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create channel for Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// Variable to track if monitoring is active
	monitoringActive := true

	// Create monitor with firewall integration
	monitor := NewEnhancedPacketMonitor(selectedInterface, fw)

	// Start monitoring in a goroutine
	go func() {
		done := make(chan error, 1)

		go func() {
			done <- monitor.Start()
		}()

		select {
		case <-ctx.Done():
			fmt.Println("\n\n⏸️  Stopping packet monitor...")
			monitor.Stop()
			return
		case err := <-done:
			if err != nil {
				fmt.Printf("❌ Error starting packet monitor: %v\n", err)
			}
		}
	}()

	fmt.Println("Type 'help' for available commands")
	fmt.Println("📝 Press Ctrl+C once to stop monitoring and show stats, twice to exit")

	// Handle Ctrl+C
	go func() {
		<-sigChan // First Ctrl+C
		if monitoringActive {
			fmt.Println("\n\n" + strings.Repeat("═", 60))
			fmt.Println("📊 MONITORING STOPPED - FIREWALL STATISTICS")
			fmt.Println(strings.Repeat("═", 60))

			// Cancel context to stop monitoring
			cancel()
			monitoringActive = false

			// Show comprehensive stats
			stats := fw.GetStats()
			fmt.Printf("📈 Total Connections:    %d\n", stats["total_connections"])
			fmt.Printf("✅ Allowed:              %d\n", stats["allowed_connections"])
			fmt.Printf("🚫 Blocked:              %d\n", stats["blocked_connections"])
			fmt.Printf("🛡️  DDoS Blocks:          %d\n", stats["ddos_blocks"])
			fmt.Printf("🤖 ML Blocks:            %d\n", stats["ml_blocks"])
			fmt.Printf("⚠️  ML Alerts:            %d\n", stats["ml_alerts"])
			fmt.Printf("📋 Total Rules:           %d\n", stats["total_rules"])
			fmt.Printf("🌐 Tracked IPs:           %d\n", stats["tracked_ips"])
			fmt.Printf("⏱️  Uptime:                %d seconds\n", stats["uptime_seconds"])

			// Show attack statistics
			attackStats := fw.GetAttackStats()
			if total, ok := attackStats["total_attacks"]; ok && total.(int) > 0 {
				fmt.Println("\n🎯 ATTACK STATISTICS")
				for _, at := range []string{"DoS", "Probe", "R2L", "U2R"} {
					if count, exists := attackStats[at]; exists {
						fmt.Printf("   %s: %d\n", at, count)
					}
				}
				if percentages, ok := attackStats["percentages"].(map[string]float64); ok {
					fmt.Println("\n📊 Attack Distribution:")
					for _, at := range []string{"DoS", "Probe", "R2L", "U2R"} {
						if pct, exists := percentages[at]; exists {
							fmt.Printf("   %s: %.1f%%\n", at, pct)
						}
					}
				}
			}

			// Show ML stats if enabled
			if fw.mlEnabled && fw.mlClient != nil && fw.mlClient.IsServiceAvailable() {
				fmt.Println("\n🤖 ML STATISTICS")
				if modelInfo, err := fw.mlClient.GetModelInfo(); err == nil {
					fmt.Printf("   Models: %d\n", len(modelInfo.Models))
					fmt.Printf("   Best model: %s (F1: %.1f%%)\n", 
						modelInfo.BestModel, 
						modelInfo.BestModelF1*100)  // Added F1 score display
				}
			}

			// Show DDoS status
			fmt.Println("\n🛡️  DDoS PROTECTION STATUS")
			fw.mu.RLock()
			activeBlocks := 0
			warnings := 0
			for _, tracker := range fw.connectionRates {
				if time.Now().Before(tracker.BlockedUntil) {
					activeBlocks++
				} else if tracker.Count > WarningThreshold {
					warnings++
				}
			}
			fw.mu.RUnlock()
			fmt.Printf("   Active blocks: %d\n", activeBlocks)
			fmt.Printf("   Warnings: %d\n", warnings)

			// Show recent logs
			logs := fw.GetLogs(5)
			if len(logs) > 0 {
				fmt.Println("\n📋 RECENT LOGS (last 5)")
				for _, log := range logs {
					actionEmoji := "✅"
					if log.Action == "BLOCK" {
						actionEmoji = "🚫"
					}
					attackInfo := ""
					if log.AttackType != "" && log.AttackType != "Normal" {
						attackInfo = fmt.Sprintf(" [%s]", log.AttackType)
					}
					fmt.Printf("   [%s] %s %s %s→%s:%d%s (%s)\n",
						log.Timestamp.Format("15:04:05"),
						actionEmoji,
						log.Action,
						log.SourceIP,
						log.DestIP,
						log.Port,
						attackInfo,
						log.Reason)
				}
			}

			fmt.Println("\n" + strings.Repeat("═", 60))
			fmt.Println("🔍 MONITORING STOPPED - You can still use commands:")
			fmt.Println("   • 'stats'      - Full statistics")
			fmt.Println("   • 'ml-status'  - ML details")
			fmt.Println("   • 'rules'      - View rules")
			fmt.Println("   • 'attacks'    - Active attacks")
			fmt.Println("   • 'attack-stats'- Attack type statistics")
			fmt.Println("   • 'logs'       - View logs")
			fmt.Println("   • 'help'       - All commands")
			fmt.Println("   • 'exit'/'q'   - Exit firewall")
			fmt.Println(strings.Repeat("═", 60))
			fmt.Print("\nfirewall> ")
		}
	}()

	// Start CLI loop
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nfirewall> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		switch command {
		case "help", "h":
			showEnhancedHelp(fw.mlEnabled)
		case "rules", "r":
			listRules(fw)
		case "add", "a":
			addRule(fw, parts[1:])
		case "add-priority", "ap":
			addRuleWithPriority(fw, parts[1:])
		case "remove", "rm":
			removeRule(fw, parts[1:])
		case "enable", "e":
			enableRule(fw, parts[1:], true)
		case "disable", "d":
			enableRule(fw, parts[1:], false)
		case "test", "t":
			testConnection(fw, parts[1:])
		case "stats", "s":
			showStats(fw)
		case "attack-stats", "as":
			showAttackStats(fw)
		case "ddos-stats", "ds":
			showDDoSStats(fw)
		case "clear-rates", "cr":
			fw.ClearRateLimits()
		case "clear", "c":
			clearScreen()
		case "exit", "quit", "q":
			fmt.Println("👋 Closing firewall...")
			os.Exit(0)
		case "attacks", "attack":
			fw.ShowActiveAttacks()
		case "logs", "l":
			showLogs(fw, parts[1:])
		case "logs-search", "ls":
			searchLogs(fw, parts[1:])
		case "logs-stats", "lst":
			showLogStats(fw)
		case "clear-logs", "cl":
			clearLogs(fw)
		case "monitor", "m":
			if !monitoringActive {
				fmt.Println("⏸️  Monitoring is stopped. Restart firewall to monitor again.")
			} else {
				showMonitoringStatus(fw)
			}
		case "analyze", "an":
			if !fw.mlEnabled || fw.mlClient == nil {
				fmt.Println("❌ ML integration not enabled. Run with -ml flag.")
				continue
			}
			handleAnalyzeCommand(fw, parts[1:])
		case "ml-status":
			if !fw.mlEnabled || fw.mlClient == nil {
				fmt.Println("❌ ML integration not enabled")
				continue
			}
			showMLStatus(fw)
		case "history", "hist":
			if !monitoringActive {
				fmt.Println("\n🚀 Launching web dashboard...")
				dashboard := NewDashboardServer(fw, 8081)
				dashboardDone := make(chan error, 1)
				go func() {
					dashboardDone <- dashboard.Start()
				}()
				<-sigChan
				dashboard.Stop()
				fmt.Println("\n📊 Dashboard closed. Returning to CLI...")
			} else {
				fmt.Println("⚠️  Please stop monitoring first with Ctrl+C")
			}
		case "feedback-stats", "fbs":
			if !fw.mlEnabled || fw.mlClient == nil {
				fmt.Println("❌ ML integration not enabled")
				continue
			}
			showFeedbackStats(fw)
		case "retrain", "rt":
			if !fw.mlEnabled || fw.mlClient == nil {
				fmt.Println("❌ ML integration not enabled")
				continue
			}
			handleRetrainCommand(fw)
		default:
			fmt.Printf("❌ Unknown command: %s. Type 'help' for available commands.\n", command)
		}
	}
}

// showAttackStats displays attack type statistics
func showAttackStats(fw *Firewall) {
	stats := fw.GetAttackStats()

	fmt.Println("\n🎯 ATTACK TYPE STATISTICS")
	fmt.Println(strings.Repeat("─", 40))

	total := stats["total_attacks"].(int)
	fmt.Printf("Total attacks detected: %d\n\n", total)

	if total > 0 {
		fmt.Println("Counts:")
		for _, at := range []string{"DoS", "Probe", "R2L", "U2R"} {
			if count, exists := stats[at]; exists {
				fmt.Printf("  %s: %d\n", at, count)
			}
		}

		fmt.Println("\nDistribution:")
		if percentages, ok := stats["percentages"].(map[string]float64); ok {
			for _, at := range []string{"DoS", "Probe", "R2L", "U2R"} {
				if pct, exists := percentages[at]; exists {
					bar := getStatBar(pct)
					fmt.Printf("  %s: %5.1f%% %s\n", at, pct, bar)
				}
			}
		}
	}
}

// getStatBar creates a simple bar for percentages
func getStatBar(percentage float64) string {
	bars := int(percentage / 5)
	result := ""
	for i := 0; i < 20; i++ {
		if i < bars {
			result += "█"
		} else {
			result += "░"
		}
	}
	return result
}

// Show feedback statistics
func showFeedbackStats(fw *Firewall) {
	fmt.Println("\n📊 FEEDBACK STATISTICS")
	fmt.Println(strings.Repeat("─", 40))

	stats, err := fw.mlClient.GetFeedbackStats()
	if err != nil {
		fmt.Printf("❌ Could not get feedback stats: %v\n", err)
		return
	}

	total := stats["total"]
	falsePos := stats["false_positive"]
	missed := stats["missed_attack"]
	correct := stats["correct_block"]

	fmt.Printf("Total feedback entries: %d\n", total)
	fmt.Printf("False positives:        %d\n", falsePos)
	fmt.Printf("Missed attacks:         %d\n", missed)
	fmt.Printf("Correct detections:     %d\n", correct)

	if total > 0 {
		fmt.Printf("\n📈 Feedback breakdown:\n")
		fmt.Printf("   • False positive rate: %.1f%%\n", float64(falsePos)/float64(total)*100)
		fmt.Printf("   • Missed attack rate:  %.1f%%\n", float64(missed)/float64(total)*100)
		fmt.Printf("   • Correct rate:        %.1f%%\n", float64(correct)/float64(total)*100)
	}

	status, err := fw.mlClient.GetRetrainStatus()
	if err == nil {
		featured := int(status["featured_samples"].(float64))
		needed := int(status["needed"].(float64))
		ready := status["ready"].(bool)

		fmt.Printf("\n📊 RETRAIN READINESS")
		fmt.Printf("\n   Featured samples: %d", featured)
		fmt.Printf("\n   Minimum required: 4500")

		if ready {
			fmt.Printf("\n   ✅ Ready for retraining! Use 'retrain' command")
		} else {
			fmt.Printf("\n   ⏳ Need %d more samples with features", needed)
			fmt.Printf("\n   Progress: %.1f%%", status["percentage"].(float64))
		}
		fmt.Println()
	}
}

func handleRetrainCommand(fw *Firewall) {
	fmt.Println("\n🔄 RETRAINING MODELS WITH FEEDBACK")
	fmt.Println(strings.Repeat("─", 50))

	status, err := fw.mlClient.GetRetrainStatus()
	if err != nil {
		fmt.Printf("❌ Could not get retrain status: %v\n", err)
		return
	}

	featured := 0
	if val, ok := status["featured_samples"]; ok {
		featured = int(val.(float64))
	}

	minRequired := 4500
	if val, ok := status["min_required"]; ok {
		minRequired = int(val.(float64))
	}

	if featured < minRequired {
		fmt.Printf("⚠️  Not enough feedback for retraining.\n")
		fmt.Printf("   Need %d more samples (have %d)\n", minRequired-featured, featured)
		fmt.Print("\nContinue anyway? (y/n): ")

		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer != "y" && answer != "yes" {
			fmt.Println("❌ Retraining cancelled")
			return
		}
	}

	fmt.Printf("📊 Starting retraining with %d samples...\n", featured)

	result, err := fw.mlClient.RetrainModels()
	if err != nil {
		fmt.Printf("❌ Retraining failed: %v\n", err)
		return
	}

	if result.Success {
		fmt.Printf("\n✅ Retraining complete!\n")
		fmt.Printf("   Accuracy: %.1f%% → %.1f%%\n",
			result.OldAccuracy*100, result.NewAccuracy*100)
		fmt.Printf("   Best model: %s\n", result.BestModel)
		fmt.Printf("   Samples used: %d\n", result.SamplesUsed)
	} else {
		fmt.Printf("\n⚠️ Retraining completed but no improvement\n")
		fmt.Printf("   Message: %s\n", result.Message)
	}
}

// Show monitoring status
func showEnhancedHelp(mlEnabled bool) {
    fmt.Println(`
Available Commands:
  help, h           - Show this help message
  rules, r          - List all firewall rules
  add, a            - Add a new rule
  add-priority, ap  - Add rule with priority
  remove, rm        - Remove a rule by ID
  enable, e         - Enable a rule
  disable, d        - Disable a rule
  test, t           - Test a connection
  stats, s          - Show firewall statistics
  attack-stats, as  - Show attack type statistics
  ddos-stats, ds    - Show DDoS protection statistics
  attacks, attack   - Show active DDoS attacks and blocked IPs
  clear-rates, cr   - Clear rate limiting data
  monitor, m        - Show real-time monitoring status
  clear, c          - Clear screen
  exit, q           - Exit firewall
  logs, l           - Show recent logs
  logs-search, ls   - Search logs by IP
  logs-stats, lst   - Show log statistics
  clear-logs, cl    - Clear log entries`)

    if mlEnabled {
        fmt.Println(`
🤖 ML Commands:
  analyze, an       - Analyze PCAP file with ML (usage: analyze <pcap-file> [threshold])
  ml-status         - Show ML service status
  feedback-stats, fbs - Show feedback statistics
  retrain, rt       - Retrain models with feedback`)
        
        fmt.Println(`
🚨 ZERO-DAY DETECTION:
  • Autoencoder-based anomaly detection enabled
  • Detects never-before-seen attack patterns
  • Shows "ZERO-DAY CANDIDATE" for highly anomalous traffic
  • Uses reconstruction error from trained autoencoder`)
    }
}

func showLogs(fw *Firewall, args []string) {
	limit := 10
	if len(args) > 0 {
		if l, err := strconv.Atoi(args[0]); err == nil {
			limit = l
		}
	}

	logs := fw.GetLogs(limit)

	if len(logs) == 0 {
		fmt.Println("📭 No logs available")
		return
	}

	fmt.Printf("📋 Recent Logs (last %d entries)\n\n", len(logs))
	fmt.Println("┌─────────────────────────┬──────────┬────────────┬────────────┬──────┬──────────┬────────────┬────────────┬──────────────────┐")
	fmt.Println("│ Timestamp               │ Action   │ Source IP  │ Dest IP    │ Port │ Protocol │ Attack     │ Reason     │ Connections/Min │")
	fmt.Println("├─────────────────────────┼──────────┼────────────┼────────────┼──────┼──────────┼────────────┼────────────┼──────────────────┤")

	for _, log := range logs {
		timestamp := log.Timestamp.Format("15:04:05.000")
		action := "✅ ALLOW"
		if log.Action == "BLOCK" {
			action = "🚫 BLOCK"
		}

		sourceIP := log.SourceIP
		if len(sourceIP) > 10 {
			sourceIP = sourceIP[:10]
		}
		destIP := log.DestIP
		if len(destIP) > 10 {
			destIP = destIP[:10]
		}

		attackType := log.AttackType
		if attackType == "" {
			attackType = "Normal"
		}
		if len(attackType) > 10 {
			attackType = attackType[:10]
		}

		reason := log.Reason
		if len(reason) > 10 {
			reason = reason[:10]
		}

		fmt.Printf("│ %-23s │ %-8s │ %-10s │ %-10s │ %-4d │ %-8s │ %-10s │ %-10s │ %-16d │\n",
			timestamp, action, sourceIP, destIP, log.Port, log.Protocol, attackType, reason, log.CountPerMin)
	}
	fmt.Println("└─────────────────────────┴──────────┴────────────┴────────────┴──────┴──────────┴────────────┴────────────┴──────────────────┘")
}

func searchLogs(fw *Firewall, args []string) {
	if len(args) < 1 {
		fmt.Println("❌ Usage: logs-search <ip-address>")
		fmt.Println("   Example: logs-search 192.168.1.100")
		return
	}

	ip := args[0]
	logs := fw.SearchLogsByIP(ip)

	if len(logs) == 0 {
		fmt.Printf("🔍 No logs found for IP: %s\n", ip)
		return
	}

	fmt.Printf("🔍 Logs for IP: %s (%d entries)\n\n", ip, len(logs))
	fmt.Println("┌─────────────────────────┬──────────┬────────────┬──────┬──────────┬────────────┬────────────┐")
	fmt.Println("│ Timestamp               │ Action   │ Dest IP    │ Port │ Protocol │ Attack     │ Reason     │")
	fmt.Println("├─────────────────────────┼──────────┼────────────┼──────┼──────────┼────────────┼────────────┤")

	for _, log := range logs {
		timestamp := log.Timestamp.Format("15:04:05.000")
		action := "✅ ALLOW"
		if log.Action == "BLOCK" {
			action = "🚫 BLOCK"
		}

		destIP := log.DestIP
		if len(destIP) > 10 {
			destIP = destIP[:10]
		}

		attackType := log.AttackType
		if attackType == "" {
			attackType = "Normal"
		}
		if len(attackType) > 8 {
			attackType = attackType[:8]
		}

		reason := log.Reason
		if len(reason) > 10 {
			reason = reason[:10]
		}

		fmt.Printf("│ %-23s │ %-8s │ %-10s │ %-4d │ %-8s │ %-10s │ %-10s │\n",
			timestamp, action, destIP, log.Port, log.Protocol, attackType, reason)
	}
	fmt.Println("└─────────────────────────┴──────────┴────────────┴──────┴──────────┴────────────┴────────────┘")
}

func showLogStats(fw *Firewall) {
	stats := fw.GetLogStats()

	fmt.Println("📊 Log Statistics")
	fmt.Println("─────────────────")
	fmt.Printf("Total Log Entries:   %d\n", stats["total_logs"])
	fmt.Printf("Allowed Connections: %d\n", stats["allowed_logs"])
	fmt.Printf("Blocked Connections: %d\n", stats["blocked_logs"])
	fmt.Printf("ML Blocks:          %d\n", stats["ml_blocks"])

	if stats["total_logs"] > 0 {
		blockRate := float64(stats["blocked_logs"]) / float64(stats["total_logs"]) * 100
		fmt.Printf("Block Rate:          %.1f%%\n", blockRate)
	}

	// Show attack counts if present
	attackCounts := 0
	for key, val := range stats {
		if strings.HasPrefix(key, "attack_") {
			if attackCounts == 0 {
				fmt.Println("\n🎯 Attacks by type:")
			}
			attackType := strings.TrimPrefix(key, "attack_")
			fmt.Printf("   %s: %d\n", attackType, val)
			attackCounts++
		}
	}
}

func clearLogs(fw *Firewall) {
	fmt.Println("ℹ️  Logs automatically rotate (keeping last 1000 entries)")
	fmt.Println("   To 'clear' logs, wait for natural rotation or restart firewall")
}

func listRules(fw *Firewall) {
	rules := fw.ListRules()

	if len(rules) == 0 {
		fmt.Println("📭 No rules configured")
		return
	}

	fmt.Printf("📋 Firewall Rules (%d total)\n\n", len(rules))

	fmt.Println("┌──────────────┬────────┬────────┬──────────────────────┬────────────┬────────┬──────────┬─────────────────────────────────┐")
	fmt.Println("│ ID           │ Type   │ Enab.  │ Source               │ Destination│ Port   │ Protocol │ Description                     │")
	fmt.Println("├──────────────┼────────┼────────┼──────────────────────┼────────────┼────────┼──────────┼─────────────────────────────────┤")

	for _, rule := range rules {
		port := "any"
		if rule.Port != 0 {
			port = strconv.Itoa(rule.Port)
		}

		desc := rule.Description
		if len(desc) > 31 {
			desc = desc[:28] + "..."
		}

		source := rule.SourceIP
		if len(source) > 20 {
			source = source[:17] + "..."
		}

		dest := rule.Destination
		if len(dest) > 10 {
			dest = dest[:7] + "..."
		}

		enabled := "✓"
		if !rule.Enabled {
			enabled = "✗"
		}

		mlFlag := ""
		if rule.MLGenerated {
			mlFlag = "🤖"
		}

		fmt.Printf("│ %-12s │ %-6s │ %-4s │ %-20s │ %-10s │ %-6s │ %-8s │ %-31s │\n",
			rule.ID+mlFlag, rule.Type, enabled, source, dest, port, rule.Protocol, desc)
	}
	fmt.Println("└──────────────┴────────┴────────┴──────────────────────┴────────────┴────────┴──────────┴─────────────────────────────────┘")
}

func addRule(fw *Firewall, args []string) {
	if len(args) < 6 {
		fmt.Println("❌ Usage: add <type> <source> <dest> <protocol> <port> <description>")
		fmt.Println("   Example: add block 192.168.1.50 any tcp 0 \"Block malicious IP\"")
		return
	}

	ruleType := args[0]
	sourceIP := args[1]
	dest := args[2]
	protocol := args[3]
	port, err := strconv.Atoi(args[4])
	if err != nil {
		fmt.Println("❌ Port must be a number (0 for any port)")
		return
	}
	description := strings.Join(args[5:], " ")

	ruleID := fw.AddRule(ruleType, sourceIP, dest, protocol, description, port)
	if strings.HasPrefix(ruleID, "error:") {
		fmt.Printf("❌ %s\n", ruleID)
	} else {
		fmt.Printf("✅ Rule added successfully: %s\n", ruleID)
	}
}

func addRuleWithPriority(fw *Firewall, args []string) {
	if len(args) < 7 {
		fmt.Println("❌ Usage: add-priority <type> <source> <dest> <protocol> <port> <priority> <description>")
		fmt.Println("   Example: add-priority allow 10.0.0.100 any any 0 50 \"High priority rule\"")
		return
	}

	ruleType := args[0]
	sourceIP := args[1]
	dest := args[2]
	protocol := args[3]
	port, err := strconv.Atoi(args[4])
	if err != nil {
		fmt.Println("❌ Port must be a number (0 for any port)")
		return
	}
	priority, err := strconv.Atoi(args[5])
	if err != nil {
		fmt.Println("❌ Priority must be a number")
		return
	}
	description := strings.Join(args[6:], " ")

	ruleID := fw.AddRuleWithPriority(ruleType, sourceIP, dest, protocol, description, port, priority)
	if strings.HasPrefix(ruleID, "error:") {
		fmt.Printf("❌ %s\n", ruleID)
	} else {
		fmt.Printf("✅ Rule added successfully: %s\n", ruleID)
	}
}

func removeRule(fw *Firewall, args []string) {
	if len(args) < 1 {
		fmt.Println("❌ Usage: remove <rule-id>")
		fmt.Println("   Example: remove rule-1234567890")
		return
	}

	ruleID := args[0]
	if fw.RemoveRule(ruleID) {
		fmt.Printf("✅ Rule %s removed successfully\n", ruleID)
	} else {
		fmt.Printf("❌ Rule %s not found\n", ruleID)
	}
}

func enableRule(fw *Firewall, args []string, enable bool) {
	if len(args) < 1 {
		if enable {
			fmt.Println("❌ Usage: enable <rule-id>")
		} else {
			fmt.Println("❌ Usage: disable <rule-id>")
		}
		return
	}

	ruleID := args[0]
	if fw.EnableRule(ruleID, enable) {
		status := "enabled"
		if !enable {
			status = "disabled"
		}
		fmt.Printf("✅ Rule %s %s successfully\n", ruleID, status)
	} else {
		fmt.Printf("❌ Rule %s not found\n", ruleID)
	}
}

func testConnection(fw *Firewall, args []string) {
	if len(args) < 4 {
		fmt.Println("❌ Usage: test <source-ip> <dest-ip> <port> <protocol>")
		fmt.Println("   Example: test 192.168.1.100 8.8.8.8 80 tcp")
		return
	}

	sourceIP := args[0]
	destIP := args[1]
	port, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Println("❌ Port must be a number")
		return
	}
	protocol := args[3]

	fmt.Printf("🔍 Testing connection: %s -> %s:%d %s\n", sourceIP, destIP, port, protocol)
	allowed := fw.CheckConnection(sourceIP, destIP, port, protocol)

	if allowed {
		fmt.Println("🎯 Result: Connection ALLOWED")
	} else {
		fmt.Println("🎯 Result: Connection BLOCKED")
	}
}

// Update the showStats function to include zero-day stats
func showStats(fw *Firewall) {
    stats := fw.GetStats()
    
    fmt.Println("📊 Firewall Statistics")
    fmt.Println("──────────────────────")
    fmt.Printf("Total Rules:          %d\n", stats["total_rules"])
    fmt.Printf("ML Rules:             %d\n", stats["ml_rules"])
    fmt.Printf("Blocked IPs:          %d\n", stats["blocked_ips"])
    fmt.Printf("Allowed IPs:          %d\n", stats["allowed_ips"])
    fmt.Printf("Total Connections:    %d\n", stats["total_connections"])
    fmt.Printf("Allowed Connections:  %d\n", stats["allowed_connections"])
    fmt.Printf("Blocked Connections:  %d\n", stats["blocked_connections"])
    fmt.Printf("DDoS Blocks:          %d\n", stats["ddos_blocks"])
    fmt.Printf("ML Blocks:            %d\n", stats["ml_blocks"])
    fmt.Printf("ML Alerts:            %d\n", stats["ml_alerts"])
    fmt.Printf("Rule Matches:         %d\n", stats["rule_matches"])
    fmt.Printf("Tracked IPs:          %d\n", stats["tracked_ips"])
    fmt.Printf("Uptime:               %d seconds\n", stats["uptime_seconds"])
    
    // Get zero-day stats from history
    history := fw.GetHistory(1000)
    zeroDayCount := 0
    for _, record := range history {
        if record.IsZeroDay {
            zeroDayCount++
        }
    }
    if zeroDayCount > 0 {
        fmt.Printf("🚨 Zero-Day Attempts:  %d\n", zeroDayCount)
    }
}

func showDDoSStats(fw *Firewall) {
	stats := fw.GetDDoSStats()

	fmt.Println("🛡️  DDoS Protection Statistics")
	fmt.Println("─────────────────────────────")
	fmt.Printf("Tracked IPs:          %v\n", stats["tracked_ips"])
	fmt.Printf("Currently Blocked:    %v\n", stats["currently_blocked"])
	fmt.Printf("Max Connections/Min:  %v\n", stats["max_connections_per_minute"])
	fmt.Printf("Block Duration:       %v minutes\n", stats["block_duration_minutes"])
}

func startRealServer(fw *Firewall, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		fmt.Printf("❌ Failed to start server on port %d: %v\n", port, err)
		return
	}

	fmt.Printf("✅ Real server listening on port %d\n", port)
	fmt.Printf("🔗 Now Python attacks will be REAL and detected!\n")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
			sourceIP := remoteAddr.IP.String()
			sourcePort := remoteAddr.Port

			allowed := fw.CheckConnection(sourceIP, "127.0.0.1", port, "tcp")

			if allowed {
				fmt.Printf("✅ ALLOWED real connection from %s:%d\n", sourceIP, sourcePort)
				conn.Write([]byte("ALLOWED\n"))
			} else {
				fmt.Printf("🚫 BLOCKED real connection from %s:%d\n", sourceIP, sourcePort)
			}

			conn.Close()
		}
	}()
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

// Handle PCAP analysis command
func handleAnalyzeCommand(fw *Firewall, args []string) {
	if len(args) < 1 {
		fmt.Println("❌ Usage: analyze <pcap-file> [threshold]")
		fmt.Println("   Example: analyze C:\\path\\to\\traffic.pcap 0.7")
		return
	}

	pcapFile := args[0]
	threshold := 0.7
	if len(args) >= 2 {
		if t, err := strconv.ParseFloat(args[1], 64); err == nil {
			threshold = t
		}
	}

	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		fmt.Printf("❌ File not found: %s\n", pcapFile)
		return
	}

	fmt.Printf("🔍 Analyzing %s with threshold %.2f (5-class detection)...\n", pcapFile, threshold)
	fmt.Println("⏳ This may take a few seconds...")

	result, err := fw.mlClient.AnalyzePCAP(pcapFile, threshold)
	if err != nil {
		fmt.Printf("❌ Analysis failed: %v\n", err)
		return
	}

	fmt.Println("\n📊 " + strings.Repeat("═", 50))
	fmt.Println("📊 PCAP ANALYSIS RESULTS (5-Class)")
	fmt.Println("📊 " + strings.Repeat("═", 50))
	fmt.Printf("   Total Packets:     %d\n", result.TotalPackets)
	fmt.Printf("   Malicious Packets: %d\n", result.MaliciousPackets)
	fmt.Printf("   Malicious %%:       %.1f%%\n", result.MaliciousPercentage)
	fmt.Printf("   Risk Level:        %s\n", result.RiskLevel)
	fmt.Printf("   Recommendation:    %s\n", result.Recommendation)

	if len(result.MaliciousIPs) > 0 {
		fmt.Println("\n🔴 " + strings.Repeat("─", 40))
		fmt.Println("🔴 MALICIOUS IPS DETECTED BY ATTACK TYPE")
		fmt.Println("🔴 " + strings.Repeat("─", 40))

		attackGroups := make(map[string][]MaliciousIP)
		for _, ip := range result.MaliciousIPs {
			attackGroups[ip.AttackType] = append(attackGroups[ip.AttackType], ip)
		}

		attackColors := map[string]string{
			"U2R":   "🟣",
			"DoS":   "🔴",
			"R2L":   "🟡",
			"Probe": "🟠",
		}

		attackOrder := []string{"U2R", "DoS", "R2L", "Probe"}

		for _, attackType := range attackOrder {
			if ips, exists := attackGroups[attackType]; exists {
				color := attackColors[attackType]
				fmt.Printf("\n%s %s ATTACKS:\n", color, attackType)
				for i, ip := range ips {
					fmt.Printf("   %d. %s (conf: %.2f)\n",
						i+1, ip.IP, ip.Confidence)
				}
			}
		}

		fmt.Print("\n🛡️  Create temporary block rules for these IPs? (y/n): ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))

		if answer == "y" || answer == "yes" {
			fmt.Println("\n📝 Creating attack-type specific rules...")

			for _, ip := range result.MaliciousIPs {
				basePriority := 50
				switch ip.AttackType {
				case "U2R":
					basePriority = 100
				case "DoS":
					basePriority = 80
				case "R2L":
					basePriority = 70
				case "Probe":
					basePriority = 60
				}

				priority := basePriority + int(ip.Confidence*20)
				if priority > 100 {
					priority = 100
				}

				expiry := 24 * time.Hour
				if ip.AttackType == "Probe" {
					expiry = 6 * time.Hour
				}

				ruleID := fw.AddMLRule("block", ip.IP, "any", "any",
					fmt.Sprintf("%s attack detected (conf=%.2f)", ip.AttackType, ip.Confidence),
					0, priority, expiry, ip.AttackType, ip.Confidence)

				color := attackColors[ip.AttackType]
				fmt.Printf("   %s Blocked %-15s [%s] (priority: %d, rule: %s)\n",
					color, ip.IP, ip.AttackType, priority, ruleID)
			}
			fmt.Println("\n✅ Rules created! Use 'rules' command to view them.")
		}
	} else {
		fmt.Println("\n✅ No malicious IPs detected in this PCAP.")
	}
}


// Show monitoring status
func showMonitoringStatus(fw *Firewall) {
	fmt.Println("📊 REAL-TIME MONITORING STATUS")
	fmt.Println("─────────────────────────────")
	fmt.Println("✅ Firewall is analyzing LIVE network traffic with 5-class ML")
	fmt.Println("👁️  Detection Mode: Showing what WOULD be blocked")
	fmt.Println("🚫 No actual packet blocking - just monitoring")
	fmt.Println("📈 Check 'stats' command for firewall decision counts")
	fmt.Println("📋 Check 'logs' command for recent detection events")
	
	// Add zero-day detection info if ML is enabled
	if fw != nil && fw.mlEnabled {
		fmt.Println("🚨 Zero-day detection: ACTIVE (autoencoder-based)")
		fmt.Println("   • Detects never-before-seen attack patterns")
		fmt.Println("   • Shows 'ZERO-DAY CANDIDATE' for anomalous traffic")
	}
}

// Show ML service status
func showMLStatus(fw *Firewall) {
    fmt.Println("\n🤖 ML SERVICE STATUS (5-Class)")
    fmt.Println(strings.Repeat("─", 40))

    if !fw.mlEnabled || fw.mlClient == nil {
        fmt.Println("❌ ML integration is disabled")
        return
    }

    if fw.mlClient.IsServiceAvailable() {
        fmt.Println("✅ Service: Connected")

        if modelInfo, err := fw.mlClient.GetModelInfo(); err == nil {
            fmt.Printf("   Models loaded: %d\n", len(modelInfo.Models))
            
            // Show F1 score instead of accuracy
            f1Score := modelInfo.BestModelF1 * 100
            fmt.Printf("   🏆 Best model: %s (F1 Score: %.1f%%)\n", 
                modelInfo.BestModel, f1Score)
            
            fmt.Printf("   Features: %d\n", modelInfo.FeaturesCount)
            fmt.Printf("   Auto-block threshold: %.0f%%\n", fw.mlThreshold*100)

            mlRuleCount := 0
            for _, rule := range fw.rules {
                if rule.MLGenerated {
                    mlRuleCount++
                }
            }
            fmt.Printf("   ML rules active: %d\n", mlRuleCount)

            fmt.Println("\n📊 Model Weights:")
            for model, weight := range modelInfo.Weights {
                fmt.Printf("   • %s: %.2f\n", model, weight)
            }
        } else {
            fmt.Printf("⚠️ Could not get model info: %v\n", err)
            if health, err := fw.mlClient.Health(); err == nil {
                fmt.Printf("   Model loaded: %v\n", health["model_loaded"])
                fmt.Printf("   Features: %v\n", health["features_count"])
            }
        }
    } else {
        fmt.Println("❌ Service: Not available")
        fmt.Println("   Start ML service with:")
        fmt.Println("   cd ../ml_pipeline && python ml_service.py")
    }
}
