// package main

// import (
//     "bufio"
//     "fmt"
//     "os"
//     "strconv"
//     "strings"
// )

// func main() {
//     fmt.Println("🛡️  Go Network Firewall - CLI Version")
//     fmt.Println("=====================================")

//     // Create firewall instance - remove "firewall." prefix
//     fw := NewFirewall()

//     // Add some default rules
//     fw.AddRule("block", "10.0.0.0/8", "any", "any", "Block internal network range", 0)
//     fw.AddRule("allow", "192.168.1.100", "any", "any", "Allow specific IP", 0)
//     fw.AddRule("block", "any", "any", "tcp", "Block SSH port", 22)

//     fmt.Println("✅ Firewall started with default rules")
//     fmt.Println("Type 'help' for available commands")

//     // Start CLI loop
//     reader := bufio.NewReader(os.Stdin)
//     for {
//         fmt.Print("\nfirewall> ")
//         input, _ := reader.ReadString('\n')
//         input = strings.TrimSpace(input)

//         if input == "" {
//             continue
//         }

//         parts := strings.Fields(input)
//         command := parts[0]

//         switch command {
//         case "help", "h":
//             showHelp()
//         case "rules", "r":
//             listRules(fw)
//         case "add", "a":
//             addRule(fw, parts[1:])
//         case "remove", "rm":
//             removeRule(fw, parts[1:])
//         case "test", "t":
//             testConnection(fw, parts[1:])
//         case "stats", "s":
//             showStats(fw)
//         case "clear", "c":
//             clearScreen()
//         case "exit", "quit", "q":
//             fmt.Println("👋 Closing firewall...")
//             return
//         default:
//             fmt.Printf("❌ Unknown command: %s. Type 'help' for available commands.\n", command)
//         }
//     }
// }

// func showHelp() {
//     fmt.Println(`
// Available Commands:
//   help, h     - Show this help message
//   rules, r    - List all firewall rules
//   add, a      - Add a new rule (usage: add <type> <source> <dest> <protocol> <port> <description>)
//   remove, rm  - Remove a rule by ID (usage: remove <rule-id>)
//   test, t     - Test a connection (usage: test <source-ip> <dest-ip> <port> <protocol>)
//   stats, s    - Show firewall statistics
//   clear, c    - Clear screen
//   exit, q     - Exit firewall

// Rule Types: block, allow
// Protocols: tcp, udp, any
// Port: 0 for any port

// Examples:
//   add block 192.168.1.50 any tcp 0 "Block malicious IP"
//   add allow 10.0.0.100 any any 0 "Allow specific host"
//   test 192.168.1.100 8.8.8.8 80 tcp
//   remove rule-1`)
// }

// // Remove "*firewall.Firewall" and use just "*Firewall" since it's in same package
// // func listRules(fw *Firewall) {
// //     rules := fw.ListRules()
    
// //     if len(rules) == 0 {
// //         fmt.Println("📭 No rules configured")
// //         return
// //     }

// //     fmt.Printf("📋 Firewall Rules (%d total)\n", len(rules))
// //     fmt.Println("┌─────────┬────────┬──────────────┬──────────┬────────┬──────────┬─────────────────────┐")
// //     fmt.Println("│ ID      │ Type   │ Source       │ Dest     │ Port   │ Protocol │ Description         │")
// //     fmt.Println("├─────────┼────────┼──────────────┼──────────┼────────┼──────────┼─────────────────────┤")
    
// //     for _, rule := range rules {
// //         port := "any"
// //         if rule.Port != 0 {
// //             port = strconv.Itoa(rule.Port)
// //         }
// //         fmt.Printf("│ %-7s │ %-6s │ %-12s │ %-8s │ %-6s │ %-8s │ %-19s │\n",
// //             rule.ID, rule.Type, rule.SourceIP, rule.Destination, port, rule.Protocol, rule.Description)
// //     }
// //     fmt.Println("└─────────┴────────┴──────────────┴──────────┴────────┴──────────┴─────────────────────┘")
// // }

// func listRules(fw *Firewall) {
//     rules := fw.ListRules()
    
//     if len(rules) == 0 {
//         fmt.Println("📭 No rules configured")
//         return
//     }

//     fmt.Printf("📋 Firewall Rules (%d total)\n\n", len(rules))
    
//     // Print header
//     fmt.Println("┌─────────┬────────┬──────────────────────┬────────────┬────────┬──────────┬────────────────────────────┐")
//     fmt.Println("│ ID      │ Type   │ Source               │ Destination│ Port   │ Protocol │ Description                │")
//     fmt.Println("├─────────┼────────┼──────────────────────┼────────────┼────────┼──────────┼────────────────────────────┤")
    
//     for _, rule := range rules {
//         // Format values
//         port := "any"
//         if rule.Port != 0 {
//             port = strconv.Itoa(rule.Port)
//         }
        
//         // Truncate long descriptions
//         desc := rule.Description
//         if len(desc) > 28 {
//             desc = desc[:25] + "..."
//         }
        
//         source := rule.SourceIP
//         if len(source) > 20 {
//             source = source[:17] + "..."
//         }
        
//         dest := rule.Destination
//         if len(dest) > 10 {
//             dest = dest[:7] + "..."
//         }
        
//         fmt.Printf("│ %-7s │ %-6s │ %-20s │ %-10s │ %-6s │ %-8s │ %-26s │\n",
//             rule.ID, rule.Type, source, dest, port, rule.Protocol, desc)
//     }
//     fmt.Println("└─────────┴────────┴──────────────────────┴────────────┴────────┴──────────┴────────────────────────────┘")
// }

// // Remove "*firewall.Firewall" 
// func addRule(fw *Firewall, args []string) {
//     if len(args) < 6 {
//         fmt.Println("❌ Usage: add <type> <source> <dest> <protocol> <port> <description>")
//         fmt.Println("   Example: add block 192.168.1.50 any tcp 0 \"Block malicious IP\"")
//         return
//     }

//     ruleType := args[0]
//     sourceIP := args[1]
//     dest := args[2]
//     protocol := args[3]
//     port, err := strconv.Atoi(args[4])
//     if err != nil {
//         fmt.Println("❌ Port must be a number (0 for any port)")
//         return
//     }
//     description := strings.Join(args[5:], " ")

//     if ruleType != "block" && ruleType != "allow" {
//         fmt.Println("❌ Type must be 'block' or 'allow'")
//         return
//     }

//     ruleID := fw.AddRule(ruleType, sourceIP, dest, protocol, description, port)
//     fmt.Printf("✅ Rule added successfully: %s\n", ruleID)
// }

// // Remove "*firewall.Firewall"
// func removeRule(fw *Firewall, args []string) {
//     if len(args) < 1 {
//         fmt.Println("❌ Usage: remove <rule-id>")
//         fmt.Println("   Example: remove rule-1")
//         return
//     }

//     ruleID := args[0]
//     if fw.RemoveRule(ruleID) {
//         fmt.Printf("✅ Rule %s removed successfully\n", ruleID)
//     } else {
//         fmt.Printf("❌ Rule %s not found\n", ruleID)
//     }
// }

// // Remove "*firewall.Firewall"
// func testConnection(fw *Firewall, args []string) {
//     if len(args) < 4 {
//         fmt.Println("❌ Usage: test <source-ip> <dest-ip> <port> <protocol>")
//         fmt.Println("   Example: test 192.168.1.100 8.8.8.8 80 tcp")
//         return
//     }

//     sourceIP := args[0]
//     destIP := args[1]
//     port, err := strconv.Atoi(args[2])
//     if err != nil {
//         fmt.Println("❌ Port must be a number")
//         return
//     }
//     protocol := args[3]

//     fmt.Printf("🔍 Testing connection: %s -> %s:%d %s\n", sourceIP, destIP, port, protocol)
//     allowed := fw.CheckConnection(sourceIP, destIP, port, protocol)
    
//     if allowed {
//         fmt.Println("🎯 Result: Connection ALLOWED")
//     } else {
//         fmt.Println("🎯 Result: Connection BLOCKED")
//     }
// }

// // Remove "*firewall.Firewall"
// func showStats(fw *Firewall) {
//     stats := fw.GetStats()
    
//     fmt.Println("📊 Firewall Statistics")
//     fmt.Println("──────────────────────")
//     fmt.Printf("Total Rules:        %d\n", stats["total_rules"])
//     fmt.Printf("Blocked IPs:        %d\n", stats["blocked_ips"])
//     fmt.Printf("Allowed IPs:        %d\n", stats["allowed_ips"])
//     fmt.Printf("Connection Checks:  %d\n", stats["total_connections"])
// }

// func clearScreen() {
//     fmt.Print("\033[H\033[2J")
// }
// package main

// import (
//     "bufio"
//     "fmt"
//     "os"
//     "net"
//     "strconv"
//     "strings"
// )

// func main() {
// fmt.Println("🛡️  Go Network Firewall - Enhanced CLI Version")
//     fmt.Println("==============================================")

//     // Create enhanced firewall instance
//     fw := NewFirewall()

//     // Add enhanced default rules with priorities
//     fw.AddRuleWithPriority("block", "10.0.0.0/8", "any", "any", "Block internal network range", 0, 10)
//     fw.AddRuleWithPriority("allow", "192.168.1.100", "any", "any", "Allow specific IP", 0, 20)
//     fw.AddRuleWithPriority("block", "any", "any", "tcp", "Block SSH port", 22, 5)
//     fw.AddRuleWithPriority("block", "any", "any", "udp", "Block UDP floods", 0, 3)
//     fw.AddRuleWithPriority("block", "192.168.1.0/24", "any", "any", "Block suspicious subnet", 0, 8)

//     // 🆕 ADD THIS LINE - Start real server
//     startRealServer(fw, 8080)

//     fmt.Println("✅ Enhanced firewall started with DDoS protection")
//     fmt.Println("✅ Real server listening on port 8080")
//     fmt.Println("Type 'help' for available commands")

//     // Start CLI loop
//     reader := bufio.NewReader(os.Stdin)
//     for {
//         fmt.Print("\nfirewall> ")
//         input, _ := reader.ReadString('\n')
//         input = strings.TrimSpace(input)

//         if input == "" {
//             continue
//         }

//         parts := strings.Fields(input)
//         command := parts[0]

//         switch command {
//         case "help", "h":
//             showEnhancedHelp()
//         case "rules", "r":
//             listRules(fw)
//         case "add", "a":
//             addRule(fw, parts[1:])
//         case "add-priority", "ap":
//             addRuleWithPriority(fw, parts[1:])
//         case "remove", "rm":
//             removeRule(fw, parts[1:])
//         case "enable", "e":
//             enableRule(fw, parts[1:], true)
//         case "disable", "d":
//             enableRule(fw, parts[1:], false)
//         case "test", "t":
//             testConnection(fw, parts[1:])
//         case "stats", "s":
//             showStats(fw)
//         case "ddos-stats", "ds":
//             showDDoSStats(fw)
//         case "clear-rates", "cr":
//             fw.ClearRateLimits()
//         case "clear", "c":
//             clearScreen()
//         case "exit", "quit", "q":
//             fmt.Println("👋 Closing firewall...")
//             return
//         case "attacks", "attack":
//             fw.ShowActiveAttacks()
//         case "logs", "l":
//             showLogs(fw, parts[1:])
//         case "logs-search", "ls":
//             searchLogs(fw, parts[1:])
//         case "logs-stats", "lst":
//             showLogStats(fw)
//         case "clear-logs", "cl":
//             clearLogs(fw)
//         default:
//             fmt.Printf("❌ Unknown command: %s. Type 'help' for available commands.\n", command)
//         }
//     }
// }

// // Update the help menu
// func showEnhancedHelp() {
//     fmt.Println(`
// Available Commands:
//   help, h           - Show this help message
//   rules, r          - List all firewall rules
//   add, a            - Add a new rule (usage: add <type> <source> <dest> <protocol> <port> <description>)
//   add-priority, ap  - Add rule with priority (usage: add-priority <type> <source> <dest> <protocol> <port> <priority> <description>)
//   remove, rm        - Remove a rule by ID (usage: remove <rule-id>)
//   enable, e         - Enable a rule (usage: enable <rule-id>)
//   disable, d        - Disable a rule (usage: disable <rule-id>)
//   test, t           - Test a connection (usage: test <source-ip> <dest-ip> <port> <protocol>)
//   stats, s          - Show firewall statistics
//   ddos-stats, ds    - Show DDoS protection statistics
//   attacks, attack   - Show active DDoS attacks and blocked IPs
//   clear-rates, cr   - Clear rate limiting data
//   clear, c          - Clear screen
//   exit, q           - Exit firewall
//   logs, l           - Show recent logs (usage: logs [count])
//   logs-search, ls   - Search logs by IP (usage: logs-search <ip>)
//   logs-stats, lst   - Show log statistics
//   clear-logs, cl    - Clear log entries

// Rule Types: block, allow
// Protocols: tcp, udp, icmp, any
// Port: 0 for any port
// Priority: Higher number = higher priority (1-100)

// Examples:
//   add block 192.168.1.50 any tcp 0 "Block malicious IP"
//   add-priority allow 10.0.0.100 any any 0 50 "High priority allow rule"
//   test 192.168.1.100 8.8.8.8 80 tcp
//   remove rule-1234567890
//   enable rule-1234567890
//   ddos-stats
//   attacks`)
// }



// main.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
    "net"
)

func main() {
	fmt.Println("🛡️  Go Network Firewall - Real-Time Detection Mode")
	fmt.Println("==================================================")

	// Create enhanced firewall instance
	fw := NewFirewall()

	// Add enhanced default rules with priorities
	fw.AddRuleWithPriority("block", "10.0.0.0/8", "any", "any", "Block internal network range", 0, 10)
	fw.AddRuleWithPriority("allow", "192.168.1.100", "any", "any", "Allow specific IP", 0, 20)
	fw.AddRuleWithPriority("block", "any", "any", "tcp", "Block SSH port", 22, 5)
	fw.AddRuleWithPriority("block", "any", "any", "udp", "Block UDP floods", 0, 3)
	fw.AddRuleWithPriority("block", "192.168.1.0/24", "any", "any", "Block suspicious subnet", 0, 8)

	fmt.Println("✅ Enhanced firewall started with DDoS protection")
	fmt.Println("🔍 Starting real-time network monitoring...")

	// 🆕 Start real-time packet monitoring with firewall integration
	go startRealTimeMonitoring(fw)

	fmt.Println("Type 'help' for available commands")

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
			showEnhancedHelp()
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
		case "ddos-stats", "ds":
			showDDoSStats(fw)
		case "clear-rates", "cr":
			fw.ClearRateLimits()
		case "clear", "c":
			clearScreen()
		case "exit", "quit", "q":
			fmt.Println("👋 Closing firewall...")
			return
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
			// 🆕 Command to show monitoring status
			showMonitoringStatus()
		default:
			fmt.Printf("❌ Unknown command: %s. Type 'help' for available commands.\n", command)
		}
	}
}

// 🆕 Start real-time packet monitoring with firewall
// startRealTimeMonitoring initializes and starts live packet monitoring with firewall integration.
// It auto-selects a network interface and runs the system in detection mode (no active blocking).
// Captures and analyzes real-time network traffic using the enhanced packet monitor.
func startRealTimeMonitoring(fw *Firewall) {
	fmt.Println("🚀 Starting Real-Time Packet Monitor with Firewall Integration")
	fmt.Println("📡 Looking for network interfaces...")

	// Get available devices
	devices, err := getNetworkInterfaces()
	if err != nil {
		fmt.Printf("❌ Error finding network interfaces: %v\n", err)
		return
	}

	// Auto-select best interface
	selectedInterface := selectInterface(devices)
	
	fmt.Printf("🎯 Starting real-time monitoring on %s\n", getInterfaceDisplayName(devices[0]))
	fmt.Println("🔍 Firewall is now analyzing LIVE network traffic!")
	fmt.Println("💡 This is DETECTION MODE - No actual blocking, just monitoring")
	fmt.Println(strings.Repeat("─", 80))

	// Create monitor with firewall integration
	monitor := NewEnhancedPacketMonitor(selectedInterface, fw)

	// Start monitoring
	if err := monitor.Start(); err != nil {
		fmt.Printf("❌ Error starting packet monitor: %v\n", err)
	}
}

// 🆕 Show monitoring status
func showMonitoringStatus() {
	fmt.Println("📊 REAL-TIME MONITORING STATUS")
	fmt.Println("─────────────────────────────")
	fmt.Println("✅ Firewall is analyzing LIVE network traffic")
	fmt.Println("👁️  Detection Mode: Showing what WOULD be blocked")
	fmt.Println("🚫 No actual packet blocking - just monitoring")
	fmt.Println("📈 Check 'stats' command for firewall decision counts")
	fmt.Println("📋 Check 'logs' command for recent detection events")
}

// 🆕 Update help menu
func showEnhancedHelp() {
	fmt.Println(`
Available Commands:
  help, h           - Show this help message
  rules, r          - List all firewall rules
  add, a            - Add a new rule (usage: add <type> <source> <dest> <protocol> <port> <description>)
  add-priority, ap  - Add rule with priority (usage: add-priority <type> <source> <dest> <protocol> <port> <priority> <description>)
  remove, rm        - Remove a rule by ID (usage: remove <rule-id>)
  enable, e         - Enable a rule (usage: enable <rule-id>)
  disable, d        - Disable a rule (usage: disable <rule-id>)
  test, t           - Test a connection (SIMULATION - usage: test <source-ip> <dest-ip> <port> <protocol>)
  stats, s          - Show firewall statistics
  ddos-stats, ds    - Show DDoS protection statistics
  attacks, attack   - Show active DDoS attacks and blocked IPs
  clear-rates, cr   - Clear rate limiting data
  monitor, m        - Show real-time monitoring status
  clear, c          - Clear screen
  exit, q           - Exit firewall
  logs, l           - Show recent logs (usage: logs [count])
  logs-search, ls   - Search logs by IP (usage: logs-search <ip>)
  logs-stats, lst   - Show log statistics
  clear-logs, cl    - Clear log entries

REAL-TIME MODE:
  • Firewall is analyzing LIVE network traffic
  • Shows what WOULD be blocked (detection only)
  • No actual packet blocking - safe to use

Rule Types: block, allow
Protocols: tcp, udp, icmp, any
Port: 0 for any port
Priority: Higher number = higher priority (1-100)

Examples:
  add block 192.168.1.50 any tcp 0 "Block malicious IP"
  add-priority allow 10.0.0.100 any any 0 50 "High priority allow rule"
  test 192.168.1.100 8.8.8.8 80 tcp
  monitor - Check real-time monitoring status`)
}

func showLogs(fw *Firewall, args []string) {
    limit := 10 // default
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
    fmt.Println("┌─────────────────────────┬──────────┬────────────┬────────────┬──────┬──────────┬────────────┬──────────────────┐")
    fmt.Println("│ Timestamp               │ Action   │ Source IP  │ Dest IP    │ Port │ Protocol │ Reason     │ Connections/Min │")
    fmt.Println("├─────────────────────────┼──────────┼────────────┼────────────┼──────┼──────────┼────────────┼──────────────────┤")
    
    for _, log := range logs {
        timestamp := log.Timestamp.Format("15:04:05.000")
        action := "✅ ALLOW"
        if log.Action == "BLOCK" {
            action = "🚫 BLOCK"
        }
        
        // Truncate long IPs if needed
        sourceIP := log.SourceIP
        if len(sourceIP) > 10 { sourceIP = sourceIP[:10] }
        destIP := log.DestIP  
        if len(destIP) > 10 { destIP = destIP[:10] }
        
        reason := log.Reason
        if len(reason) > 10 { reason = reason[:10] }
        
        fmt.Printf("│ %-23s │ %-8s │ %-10s │ %-10s │ %-4d │ %-8s │ %-10s │ %-16d │\n",
            timestamp, action, sourceIP, destIP, log.Port, log.Protocol, reason, log.CountPerMin)
    }
    fmt.Println("└─────────────────────────┴──────────┴────────────┴────────────┴──────┴──────────┴────────────┴──────────────────┘")
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
    fmt.Println("┌─────────────────────────┬──────────┬────────────┬──────┬──────────┬────────────┐")
    fmt.Println("│ Timestamp               │ Action   │ Dest IP    │ Port │ Protocol │ Reason     │")
    fmt.Println("├─────────────────────────┼──────────┼────────────┼──────┼──────────┼────────────┤")
    
    for _, log := range logs {
        timestamp := log.Timestamp.Format("15:04:05.000")
        action := "✅ ALLOW"
        if log.Action == "BLOCK" {
            action = "🚫 BLOCK"
        }
        
        destIP := log.DestIP  
        if len(destIP) > 10 { destIP = destIP[:10] }
        
        reason := log.Reason
        if len(reason) > 10 { reason = reason[:10] }
        
        fmt.Printf("│ %-23s │ %-8s │ %-10s │ %-4d │ %-8s │ %-10s │\n",
            timestamp, action, destIP, log.Port, log.Protocol, reason)
    }
    fmt.Println("└─────────────────────────┴──────────┴────────────┴──────┴──────────┴────────────┘")
}

func showLogStats(fw *Firewall) {
    stats := fw.GetLogStats()
    
    fmt.Println("📊 Log Statistics")
    fmt.Println("─────────────────")
    fmt.Printf("Total Log Entries:   %d\n", stats["total_logs"])
    fmt.Printf("Allowed Connections: %d\n", stats["allowed_logs"]) 
    fmt.Printf("Blocked Connections: %d\n", stats["blocked_logs"])
    
    if stats["total_logs"] > 0 {
        blockRate := float64(stats["blocked_logs"]) / float64(stats["total_logs"]) * 100
        fmt.Printf("Block Rate:          %.1f%%\n", blockRate)
    }
}

func clearLogs(fw *Firewall) {
    // For now, we'll just show a message since logs auto-rotate
    // In a real implementation, you'd add a ClearLogs method to firewall
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
    
    // Print header
    fmt.Println("┌──────────────┬────────┬────────┬──────────────────────┬────────────┬────────┬──────────┬────────────────────────────┐")
    fmt.Println("│ ID           │ Type   │ Enab.  │ Source               │ Destination│ Port   │ Protocol │ Description                │")
    fmt.Println("├──────────────┼────────┼────────┼──────────────────────┼────────────┼────────┼──────────┼────────────────────────────┤")
    
    for _, rule := range rules {
        // Format values
        port := "any"
        if rule.Port != 0 {
            port = strconv.Itoa(rule.Port)
        }
        
        // Truncate long descriptions
        desc := rule.Description
        if len(desc) > 28 {
            desc = desc[:25] + "..."
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
        
        fmt.Printf("│ %-12s │ %-6s │ %-6s │ %-20s │ %-10s │ %-6s │ %-8s │ %-26s │\n",
            rule.ID, rule.Type, enabled, source, dest, port, rule.Protocol, desc)
    }
    fmt.Println("└──────────────┴────────┴────────┴──────────────────────┴────────────┴────────┴──────────┴────────────────────────────┘")
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

func showStats(fw *Firewall) {
    stats := fw.GetStats()
    
    fmt.Println("📊 Firewall Statistics")
    fmt.Println("──────────────────────")
    fmt.Printf("Total Rules:          %d\n", stats["total_rules"])
    fmt.Printf("Blocked IPs:          %d\n", stats["blocked_ips"])
    fmt.Printf("Allowed IPs:          %d\n", stats["allowed_ips"])
    fmt.Printf("Total Connections:    %d\n", stats["total_connections"])
    fmt.Printf("Allowed Connections:  %d\n", stats["allowed_connections"])
    fmt.Printf("Blocked Connections:  %d\n", stats["blocked_connections"])
    fmt.Printf("DDoS Blocks:          %d\n", stats["ddos_blocks"])
    fmt.Printf("Rule Matches:         %d\n", stats["rule_matches"])
    fmt.Printf("Tracked IPs:          %d\n", stats["tracked_ips"])
    fmt.Printf("Uptime:               %d seconds\n", stats["uptime_seconds"])
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
            
            // Use firewall to check connection
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
