// package main

// import (
//     "fmt"
//     "net"
//     "sync"
//     "time"
// )

// // Firewall represents our network security system
// type Firewall struct {
//     mu          sync.RWMutex       // Protects concurrent access to rules
//     rules       []Rule             // List of firewall rules
//     blockedIPs  map[string]bool    // Quick IP blocking lookup
//     allowedIPs  map[string]bool    // Quick IP allowing lookup
//     connections map[string]int     // Track active connections
// }

// // Rule defines a single firewall rule
// type Rule struct {
//     ID          string
//     Type        string    // "block" or "allow"
//     SourceIP    string    // IP or CIDR like "192.168.1.100" or "192.168.1.0/24"
//     Destination string    // Destination IP or "any"
//     Port        int       // 0 means any port
//     Protocol    string    // "tcp", "udp", or "any"
//     Description string
//     CreatedAt   time.Time
// }

// // NewFirewall creates a new firewall instance
// func NewFirewall() *Firewall {
//     return &Firewall{
//         rules:       make([]Rule, 0),
//         blockedIPs:  make(map[string]bool),
//         allowedIPs:  make(map[string]bool),
//         connections: make(map[string]int),
//     }
// }

// // AddRule adds a new firewall rule
// func (fw *Firewall) AddRule(ruleType, sourceIP, dest, protocol, description string, port int) string {
//     fw.mu.Lock()
//     defer fw.mu.Unlock()

//     // Create new rule
//     rule := Rule{
//         ID:          fmt.Sprintf("rule-%d", len(fw.rules)+1),
//         Type:        ruleType,
//         SourceIP:    sourceIP,
//         Destination: dest,
//         Port:        port,
//         Protocol:    protocol,
//         Description: description,
//         CreatedAt:   time.Now(),
//     }

//     // Add to rules list
//     fw.rules = append(fw.rules, rule)

//     // Update quick lookup maps
//     if ruleType == "block" {
//         fw.blockedIPs[sourceIP] = true
//     } else if ruleType == "allow" {
//         fw.allowedIPs[sourceIP] = true
//     }

//     return rule.ID
// }

// // CheckConnection checks if a connection should be allowed
// func (fw *Firewall) CheckConnection(sourceIP, destIP string, port int, protocol string) bool {
//     fw.mu.RLock()
//     defer fw.mu.RUnlock()

//     // Track connection attempt
//     fw.connections[sourceIP]++

//     // First, check quick block list
//     if fw.blockedIPs[sourceIP] {
//         fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (IP blocked)\n", sourceIP, destIP, port, protocol)
//         return false
//     }

//     // Check quick allow list
//     if fw.allowedIPs[sourceIP] {
//         fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (IP allowed)\n", sourceIP, destIP, port, protocol)
//         return true
//     }

//     // Check all rules in order
//     for _, rule := range fw.rules {
//         if fw.matchRule(rule, sourceIP, destIP, port, protocol) {
//             if rule.Type == "allow" {
//                 fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
//                 return true
//             } else {
//                 fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
//                 return false
//             }
//         }
//     }

//     // Default: allow if no rules match
//     fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Default allow)\n", sourceIP, destIP, port, protocol)
//     return true
// }

// // matchRule checks if a connection matches a specific rule
// func (fw *Firewall) matchRule(rule Rule, sourceIP, destIP string, port int, protocol string) bool {
//     // Check source IP match
//     if rule.SourceIP != "any" && !fw.matchIP(rule.SourceIP, sourceIP) {
//         return false
//     }

//     // Check destination
//     if rule.Destination != "any" && rule.Destination != destIP {
//         return false
//     }

//     // Check port
//     if rule.Port != 0 && rule.Port != port {
//         return false
//     }

//     // Check protocol
//     if rule.Protocol != "any" && rule.Protocol != protocol {
//         return false
//     }

//     return true
// }

// // matchIP checks if an IP matches a CIDR or exact IP
// func (fw *Firewall) matchIP(cidrOrIP, ip string) bool {
//     // Exact match
//     if cidrOrIP == ip {
//         return true
//     }

//     // CIDR match
//     _, ipnet, err := net.ParseCIDR(cidrOrIP)
//     if err != nil {
//         return false
//     }

//     parsedIP := net.ParseIP(ip)
//     return ipnet.Contains(parsedIP)
// }

// // RemoveRule removes a rule by ID
// func (fw *Firewall) RemoveRule(ruleID string) bool {
//     fw.mu.Lock()
//     defer fw.mu.Unlock()

//     for i, rule := range fw.rules {
//         if rule.ID == ruleID {
//             // Remove from quick lookup maps
//             if rule.Type == "block" {
//                 delete(fw.blockedIPs, rule.SourceIP)
//             } else if rule.Type == "allow" {
//                 delete(fw.allowedIPs, rule.SourceIP)
//             }

//             // Remove from rules slice
//             fw.rules = append(fw.rules[:i], fw.rules[i+1:]...)
//             return true
//         }
//     }
//     return false
// }

// // ListRules returns all current rules
// func (fw *Firewall) ListRules() []Rule {
//     fw.mu.RLock()
//     defer fw.mu.RUnlock()
//     return fw.rules
// }

// // GetStats returns firewall statistics
// func (fw *Firewall) GetStats() map[string]int {
//     fw.mu.RLock()
//     defer fw.mu.RUnlock()

//     stats := make(map[string]int)
//     stats["total_rules"] = len(fw.rules)
//     stats["blocked_ips"] = len(fw.blockedIPs)
//     stats["allowed_ips"] = len(fw.allowedIPs)

//     totalConnections := 0
//     for _, count := range fw.connections {
//         totalConnections += count
//     }
//     stats["total_connections"] = totalConnections

//     return stats
// }

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	// "golang.org/x/text/unicode/rangetable"
	// "golang.org/x/tools/go/analysis/passes/defers"
)

// Firewall represents our enhanced network security system
type Firewall struct {
    mu                sync.RWMutex       // Protects concurrent access to rules
    rules             []Rule             // List of firewall rules
    blockedIPs        map[string]bool    // Quick IP blocking lookup
    allowedIPs        map[string]bool    // Quick IP allowing lookup
    connections       map[string]int     // Track active connections
    connectionRates   map[string]*RateTracker // DDoS protection
    stats             *Statistics 
    logs              []LogEntry
    logMutex          sync.RWMutex
    logFile           *os.File
}



type LogEntry struct {
    Timestamp     time.Time `json:"timestamp"`
    SourceIP      string    `json:"source_ip"`
    DestIP        string    `json:"dest_ip"`
    Port          int       `json:"port"`
    Protocol      string    `json:"protocol"`
    Action        string    `json:"action"`      // "ALLOW" or "BLOCK"
    Reason        string    `json:"reason"`      // "RULE_MATCH", "DDOS_BLOCK", etc.
    RuleID        string    `json:"rule_id"`
    ConnectionID  string    `json:"connection_id"`
    CountPerMin   int       `json:"count_per_min"` // Current rate
}

// log reasons constants

const (
    ReasonRuleMatch     = "RULE_MATCH"
    ReasonIPBlockList   = "IP_BLOCKLIST" 
    ReasonIPAllowList   = "IP_ALLOWLIST"
    ReasonDDOSBlock     = "DDOS_PROTECTION"
    ReasonDefaultAllow  = "DEFAULT_ALLOW"
)

// RateTracker tracks connection rates for DDoS protection
type RateTracker struct {
    Count         int
    LastReset     time.Time
    BlockedUntil  time.Time
    FirstSeen     time.Time
}

// Statistics tracks comprehensive firewall stats
type Statistics struct {
    TotalConnections  int
    BlockedConnections int
    AllowedConnections int
    DDosBlocks        int
    RuleMatches       int
    StartTime         time.Time
}

// Rule defines a single firewall rule
type Rule struct {
    ID          string
    Type        string    // "block" or "allow"
    SourceIP    string    // IP or CIDR like "192.168.1.100" or "192.168.1.0/24"
    Destination string    // Destination IP or "any"
    Port        int       // 0 means any port
    Protocol    string    // "tcp", "udp", "icmp", or "any"
    Description string
    CreatedAt   time.Time
    Priority    int       // Higher number = higher priority
    Enabled     bool      // Rule can be enabled/disabled
}

// Constants for DDoS protection
const (
    MaxConnectionsPerMinute = 30  // Lower for easier testing
    WarningThreshold        = 15  // Warn when reaching this many connections
    BlockDuration           = 2 * time.Minute // Shorter for testing
    CleanupInterval         = 5 * time.Minute
)

// NewFirewall creates a new enhanced firewall instance
func NewFirewall() *Firewall {
    fw := &Firewall{
        rules:           make([]Rule, 0),
        blockedIPs:      make(map[string]bool),
        allowedIPs:      make(map[string]bool),
        connections:     make(map[string]int),
        connectionRates: make(map[string]*RateTracker),
        stats: &Statistics{
            StartTime: time.Now(),
        },
    }
    
    // Start background cleanup goroutine
    go fw.cleanupRoutine()
    
    return fw
}

// cleanupRoutine periodically cleans up old rate trackers
func (fw *Firewall) cleanupRoutine() {
    ticker := time.NewTicker(CleanupInterval)
    defer ticker.Stop()
    
    for range ticker.C {
        fw.mu.Lock()
        now := time.Now()
        for ip, tracker := range fw.connectionRates {
            // Remove trackers older than 1 hour for IPs that aren't currently blocked
            if now.Sub(tracker.FirstSeen) > time.Hour && now.After(tracker.BlockedUntil) {
                delete(fw.connectionRates, ip)
            }
        }
        fw.mu.Unlock()
    }
}

// AddRule adds a new firewall rule with priority
func (fw *Firewall) AddRule(ruleType, sourceIP, dest, protocol, description string, port int) string {
    return fw.AddRuleWithPriority(ruleType, sourceIP, dest, protocol, description, port, 1)
}

// AddRuleWithPriority adds a new firewall rule with custom priority
func (fw *Firewall) AddRuleWithPriority(ruleType, sourceIP, dest, protocol, description string, port int, priority int) string {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    // Validate input
    if !isValidRuleType(ruleType) {
        return "error: invalid rule type"
    }
    
    if !isValidProtocol(protocol) {
        return "error: invalid protocol"
    }

    // Create new rule
    rule := Rule{
        ID:          fmt.Sprintf("rule-%d-%d", time.Now().Unix(), len(fw.rules)+1),
        Type:        ruleType,
        SourceIP:    sourceIP,
        Destination: dest,
        Port:        port,
        Protocol:    protocol,
        Description: description,
        CreatedAt:   time.Now(),
        Priority:    priority,
        Enabled:     true,
    }

    // Add to rules list (insert sorted by priority)
    fw.insertRuleSorted(rule)

    // Update quick lookup maps
    if ruleType == "block" {
        fw.blockedIPs[sourceIP] = true
    } else if ruleType == "allow" {
        fw.allowedIPs[sourceIP] = true
    }

    return rule.ID
}

// insertRuleSorted inserts rule maintaining priority order
func (fw *Firewall) insertRuleSorted(rule Rule) {
    for i, existingRule := range fw.rules {
        if rule.Priority > existingRule.Priority {
            fw.rules = append(fw.rules[:i], append([]Rule{rule}, fw.rules[i:]...)...)
            return
        }
    }
    fw.rules = append(fw.rules, rule)
}

// CheckConnection checks if a connection should be allowed with DDoS protection
// func (fw *Firewall) CheckConnection(sourceIP, destIP string, port int, protocol string) bool {
//     fw.mu.Lock()
//     defer fw.mu.Unlock()

//     fw.stats.TotalConnections++

//     // DDoS Protection: Check rate limiting first
//     if fw.isRateLimited(sourceIP) {
//         fw.stats.BlockedConnections++
//         fw.stats.DDosBlocks++
//         fmt.Printf("🚨 REAL-TIME DDoS BLOCKED: %s -> %s:%d %s (Rate limit exceeded)\n", sourceIP, destIP, port, protocol)
//         return false
//     }

//     // Update connection tracking and check for warnings
//     fw.connections[sourceIP]++
//     currentCount := fw.updateRateTracker(sourceIP)
    
//     // Show warning when approaching limit
//     if currentCount == WarningThreshold {
//         fmt.Printf("⚠️  DDoS WARNING: IP %s is making suspicious connections (%d/min)\n", sourceIP, currentCount)
//     }
    
//     // Show alert when blocking occurs
//     if currentCount >= MaxConnectionsPerMinute {
//         fmt.Printf("🔴 CRITICAL: DDoS Attack Detected from %s! Blocking for %v\n", sourceIP, BlockDuration)
//     }

//     // First, check quick block list
//     if fw.blockedIPs[sourceIP] {
//         fw.stats.BlockedConnections++
//         fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (IP in block list)\n", sourceIP, destIP, port, protocol)
//         return false
//     }

//     // Check quick allow list
//     if fw.allowedIPs[sourceIP] {
//         fw.stats.AllowedConnections++
//         fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (IP in allow list)\n", sourceIP, destIP, port, protocol)
//         return true
//     }

//     // Check all rules in priority order
//     for _, rule := range fw.rules {
//         if !rule.Enabled {
//             continue
//         }
        
//         if fw.matchRule(rule, sourceIP, destIP, port, protocol) {
//             fw.stats.RuleMatches++
//             if rule.Type == "allow" {
//                 fw.stats.AllowedConnections++
//                 fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
//                 return true
//             } else {
//                 fw.stats.BlockedConnections++
//                 fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
//                 return false
//             }
//         }
//     }

//     // Default: allow if no rules match
//     fw.stats.AllowedConnections++
//     fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Default allow)\n", sourceIP, destIP, port, protocol)
//     return true
// }

// CheckConnection checks if a connection should be allowed with DDoS protection AND LOGGING
func (fw *Firewall) CheckConnection(sourceIP, destIP string, port int, protocol string) bool {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    fw.stats.TotalConnections++
    
    connectionID := fmt.Sprintf("%s-%d-%s", sourceIP, port, protocol)
    currentCount := fw.updateRateTracker(sourceIP)

    // Create log entry base - we'll fill this as we make decisions
    logEntry := LogEntry{
        Timestamp:    time.Now(),
        SourceIP:     sourceIP,
        DestIP:       destIP,
        Port:         port,
        Protocol:     protocol,
        CountPerMin:  currentCount,
        ConnectionID: connectionID,
    }

    // DDoS Protection: Check rate limiting first
    if fw.isRateLimited(sourceIP) {
        fw.stats.BlockedConnections++
        fw.stats.DDosBlocks++
        
        logEntry.Action = "BLOCK"
        logEntry.Reason = ReasonDDOSBlock
        fw.addLog(logEntry)
        
        fmt.Printf("🚨 REAL-TIME DDoS BLOCKED: %s -> %s:%d %s (Rate limit exceeded)\n", sourceIP, destIP, port, protocol)
        return false
    }

    // Update connection tracking and check for warnings
    fw.connections[sourceIP]++
    
    // Show warning when approaching limit
    if currentCount == WarningThreshold {
        fmt.Printf("⚠️  DDoS WARNING: IP %s is making suspicious connections (%d/min)\n", sourceIP, currentCount)
    }
    
    // Show alert when blocking occurs
    if currentCount >= MaxConnectionsPerMinute {
        fmt.Printf("🔴 CRITICAL: DDoS Attack Detected from %s! Blocking for %v\n", sourceIP, BlockDuration)
    }

    // First, check quick block list
    if fw.blockedIPs[sourceIP] {
        fw.stats.BlockedConnections++
        
        logEntry.Action = "BLOCK"
        logEntry.Reason = ReasonIPBlockList
        fw.addLog(logEntry)
        
        fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (IP in block list)\n", sourceIP, destIP, port, protocol)
        return false
    }

    // Check quick allow list
    if fw.allowedIPs[sourceIP] {
        fw.stats.AllowedConnections++
        
        logEntry.Action = "ALLOW"
        logEntry.Reason = ReasonIPAllowList
        fw.addLog(logEntry)
        
        fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (IP in allow list)\n", sourceIP, destIP, port, protocol)
        return true
    }

    // Check all rules in priority order
    for _, rule := range fw.rules {
        if !rule.Enabled {
            continue
        }
        
        if fw.matchRule(rule, sourceIP, destIP, port, protocol) {
            fw.stats.RuleMatches++
            
            logEntry.RuleID = rule.ID
            
            if rule.Type == "allow" {
                fw.stats.AllowedConnections++
                
                logEntry.Action = "ALLOW"
                logEntry.Reason = ReasonRuleMatch
                fw.addLog(logEntry)
                
                fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
                return true
            } else {
                fw.stats.BlockedConnections++
                
                logEntry.Action = "BLOCK"
                logEntry.Reason = ReasonRuleMatch
                fw.addLog(logEntry)
                
                fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (Rule: %s)\n", sourceIP, destIP, port, protocol, rule.Description)
                return false
            }
        }
    }

    // Default: allow if no rules match
    fw.stats.AllowedConnections++
    
    logEntry.Action = "ALLOW"
    logEntry.Reason = ReasonDefaultAllow
    fw.addLog(logEntry)
    
    fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Default allow)\n", sourceIP, destIP, port, protocol)
    return true
}


// helper methode to convert map to slice for persistence

func (fw *Firewall) mapKeys(m map[string]bool) []string {
    keys := make([]string , 0 , len(m))

    for k := range m {
        keys = append(keys, k)
    }
    return keys
}

func (fw *Firewall) mapToSlice(s []string) map[string]bool {
    m := make(map[string]bool)

    for _, v := range s{
        m[v] = true
    }
    return m
}

func (fw *Firewall) updateRateTracker(ip string) int {
    tracker, exists := fw.connectionRates[ip]
    if !exists {
        tracker = &RateTracker{
            Count:     1,
            LastReset: time.Now(),
            FirstSeen: time.Now(),
        }
        fw.connectionRates[ip] = tracker
        return 1
    } else {
        tracker.Count++
        return tracker.Count
    }
}

// isRateLimited checks if an IP has exceeded connection rate limits
func (fw *Firewall) isRateLimited(ip string) bool {
    tracker, exists := fw.connectionRates[ip]
    if !exists {
        return false
    }

    // Check if IP is temporarily blocked
    if time.Now().Before(tracker.BlockedUntil) {
        remaining := time.Until(tracker.BlockedUntil).Round(time.Second)
        fmt.Printf("🛡️  IP %s is blocked for %v more (DDoS protection)\n", ip, remaining)
        return true
    }

    // Reset counter if minute has passed
    if time.Since(tracker.LastReset) > time.Minute {
        tracker.Count = 0
        tracker.LastReset = time.Now()
        fmt.Printf("🔄 Rate limit reset for IP %s\n", ip)
        return false
    }

    // Check if exceeding limit
    if tracker.Count >= MaxConnectionsPerMinute {
        tracker.BlockedUntil = time.Now().Add(BlockDuration)
        fmt.Printf("🔴 DDoS ATTACK MITIGATED: Blocked IP %s for %v (%d connections/min)\n", 
            ip, BlockDuration, tracker.Count)
        return true
    }

    return false
}



// matchRule checks if a connection matches a specific rule with enhanced matching
func (fw *Firewall) matchRule(rule Rule, sourceIP, destIP string, port int, protocol string) bool {
    // Check source IP match
    if rule.SourceIP != "any" && !fw.matchIP(rule.SourceIP, sourceIP) {
        return false
    }

    // Check destination
    if rule.Destination != "any" && !fw.matchIP(rule.Destination, destIP) {
        return false
    }

    // Check port
    if rule.Port != 0 && rule.Port != port {
        return false
    }

    // Check protocol (case insensitive)
    if rule.Protocol != "any" && !strings.EqualFold(rule.Protocol, protocol) {
        return false
    }

    return true
}

// matchIP checks if an IP matches a CIDR or exact IP with enhanced matching
func (fw *Firewall) matchIP(cidrOrIP, ip string) bool {
    // Exact match
    if cidrOrIP == ip {
        return true
    }

    // CIDR match
    _, ipnet, err := net.ParseCIDR(cidrOrIP)
    if err == nil {
        parsedIP := net.ParseIP(ip)
        if parsedIP != nil {
            return ipnet.Contains(parsedIP)
        }
    }

    // Wildcard matching for subnets (e.g., "192.16
    // 
    // .1.*")
    if strings.Contains(cidrOrIP, "*") {
        cidrParts := strings.Split(cidrOrIP, ".")
        ipParts := strings.Split(ip, ".")
        
        if len(cidrParts) != 4 || len(ipParts) != 4 {
            return false
        }
        
        for i := 0; i < 4; i++ {
            if cidrParts[i] != "*" && cidrParts[i] != ipParts[i] {
                return false
            }
        }
        return true
    }

    return false
}

// RemoveRule removes a rule by ID
func (fw *Firewall) RemoveRule(ruleID string) bool {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    for i, rule := range fw.rules {
        if rule.ID == ruleID {
            // Remove from quick lookup maps
            if rule.Type == "block" {
                delete(fw.blockedIPs, rule.SourceIP)
            } else if rule.Type == "allow" {
                delete(fw.allowedIPs, rule.SourceIP)
            }

            // Remove from rules slice
            fw.rules = append(fw.rules[:i], fw.rules[i+1:]...)
            return true
        }
    }
    return false
}

// EnableRule enables/disables a rule by ID
func (fw *Firewall) EnableRule(ruleID string, enable bool) bool {
    fw.mu.Lock()
    defer fw.mu.Unlock()

    for i, rule := range fw.rules {
        if rule.ID == ruleID {
            fw.rules[i].Enabled = enable
            return true
        }
    }
    return false
}

// ListRules returns all current rules
func (fw *Firewall) ListRules() []Rule {
    fw.mu.RLock()
    defer fw.mu.RUnlock()
    
    // Return a copy to prevent external modification
    rulesCopy := make([]Rule, len(fw.rules))
    copy(rulesCopy, fw.rules)
    return rulesCopy
}

// GetStats returns enhanced firewall statistics
func (fw *Firewall) GetStats() map[string]int {
    fw.mu.RLock()
    defer fw.mu.RUnlock()

    stats := make(map[string]int)
    stats["total_rules"] = len(fw.rules)
    stats["blocked_ips"] = len(fw.blockedIPs)
    stats["allowed_ips"] = len(fw.allowedIPs)
    stats["total_connections"] = fw.stats.TotalConnections
    stats["blocked_connections"] = fw.stats.BlockedConnections
    stats["allowed_connections"] = fw.stats.AllowedConnections
    stats["ddos_blocks"] = fw.stats.DDosBlocks
    stats["rule_matches"] = fw.stats.RuleMatches
    stats["tracked_ips"] = len(fw.connectionRates)
    
    // Calculate uptime
    uptime := int(time.Since(fw.stats.StartTime).Seconds())
    stats["uptime_seconds"] = uptime

    return stats
}

// GetDDoSStats returns DDoS protection statistics
func (fw *Firewall) GetDDoSStats() map[string]interface{} {
    fw.mu.RLock()
    defer fw.mu.RUnlock()

    stats := make(map[string]interface{})
    stats["tracked_ips"] = len(fw.connectionRates)
    
    blockedCount := 0
    for _, tracker := range fw.connectionRates {
        if time.Now().Before(tracker.BlockedUntil) {
            blockedCount++
        }
    }
    stats["currently_blocked"] = blockedCount
    stats["max_connections_per_minute"] = MaxConnectionsPerMinute
    stats["block_duration_minutes"] = BlockDuration.Minutes()

    return stats
}

// ClearRateLimits clears all rate limiting data
func (fw *Firewall) ClearRateLimits() {
    fw.mu.Lock()
    defer fw.mu.Unlock()
    
    fw.connectionRates = make(map[string]*RateTracker)
    fmt.Println("✅ Rate limiting data cleared")
}

// Helper validation functions
func isValidRuleType(ruleType string) bool {
    return ruleType == "block" || ruleType == "allow"
}

func isValidProtocol(protocol string) bool {
    switch strings.ToLower(protocol) {
    case "tcp", "udp", "icmp", "any":
        return true
    default:
        return false
    }
}


func (fw *Firewall) ShowActiveAttacks() {
    fw.mu.RLock()
    defer fw.mu.RUnlock()

    now := time.Now()
    activeAttacks := 0
    
    fmt.Println("\n🛡️  ACTIVE DDoS PROTECTION STATUS")
    fmt.Println("=================================")
    
    for ip, tracker := range fw.connectionRates {
        if now.Before(tracker.BlockedUntil) {
            activeAttacks++
            remaining := time.Until(tracker.BlockedUntil).Round(time.Second)
            fmt.Printf("🔴 IP: %s | Blocked for: %v | Connections: %d/min\n", 
                ip, remaining, tracker.Count)
        } else if tracker.Count > WarningThreshold {
            fmt.Printf("🟡 IP: %s | Warning: %d connections/min\n", ip, tracker.Count)
        }
    }
    
    if activeAttacks == 0 {
        fmt.Println("✅ No active DDoS attacks detected")
    } else {
        fmt.Printf("🚨 %d IPs currently being blocked for DDoS attacks\n", activeAttacks)
    }
}

func (fw *Firewall ) addLog(entry LogEntry){
    fw.logMutex.Lock()
    defer fw.logMutex.Unlock()

    fw.logs = append(fw.logs, entry)

    // simple rotaion - keep last 1000 entries

    if len(fw.logs) > 1000 {
        fw.logs = fw.logs[1 : ] // remove the oldest
    }

    // Optional: Write to file (uncomment if you want file logging)
    // if fw.logFile != nil {
    //     logJSON, _ := json.Marshal(entry)
    //     fw.logFile.WriteString(string(logJSON) + "\n")
    // }
}



// get the recent logs
func (fw *Firewall) GetLogs(limit int) []LogEntry{
    fw.logMutex.RLock()
    defer fw.logMutex.RUnlock()

    if limit <= 0 || limit > len(fw.logs){
        limit = len(fw.logs)
    }
    return fw.logs[len(fw.logs)-limit:]
}

// Serach by the ip 

func (fw *Firewall) SearchLogsByIP(ip string) []LogEntry{
    fw.logMutex.RLock()
    defer fw.logMutex.RUnlock()



    var results []LogEntry

    for _, log := range fw.logs {
        if log.SourceIP == ip || log.DestIP == ip {
            results = append(results, log)
        }
    }
    return results
}

// get the log statics 
func (fw *Firewall) GetLogStats()  map[string]int{
    fw.logMutex.RLock()
    defer fw.logMutex.RUnlock()

    stats := make(map[string]int)
    stats["total_logs"] = len(fw.logs)

    allowed := 0
    blocked := 0

    for _, log := range fw.logs {
        if log.Action == "ALLOW" {
            allowed++
        }else{
            blocked++
        }
    }
    stats["allowed_logs"] = allowed
    stats["blocked_logs"] = blocked

    return stats
}