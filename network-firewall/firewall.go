package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Firewall represents our enhanced network security system with 5-class ML
type Firewall struct {
	mu                sync.RWMutex
	rules             []Rule
	blockedIPs        map[string]bool
	allowedIPs        map[string]bool
	connections       map[string]int
	connectionRates   map[string]*RateTracker
	stats             *Statistics
	logs              []LogEntry
	logMutex          sync.RWMutex
	logFile           *os.File
	mlClient          *MLClient
	mlEnabled         bool
	mlThreshold       float64
	history           []*ConnectionRecord
	historyLock       sync.RWMutex
	nextID            int
	attackCounts      map[string]int           // Track attacks by type
	attackMutex       sync.RWMutex
	mlRuleCache       map[string]*MLRuleInfo   // Cache for ML-generated rules
	cacheMutex        sync.RWMutex
}

type MLRuleInfo struct {
	RuleID      string
	AttackType  string
	Confidence  float64
	ExpiresAt   time.Time
	PacketCount int
}

type ConnectionRecord struct {
    ID              int                    `json:"id"`
    Timestamp       time.Time              `json:"timestamp"`
    SourceIP        string                 `json:"source_ip"`
    DestIP          string                 `json:"dest_ip"`
    Port            int                    `json:"port"`
    Protocol        string                 `json:"protocol"`
    MLScore         float64                `json:"ml_score"`
    ThreatLevel     string                 `json:"threat_level"`
    MLColor         string                 `json:"ml_color"`
    ModelScores     map[string]float64     `json:"model_scores"`
    Consensus       float64                `json:"consensus"`
    ConsensusLevel  string                 `json:"consensus_level"`
    FirewallAction  string                 `json:"firewall_action"`
    RuleID          string                 `json:"rule_id,omitempty"`
    DDoSCount       int                    `json:"ddos_count"`
    DDoSLimited     bool                    `json:"ddos_limited"`
    Feedback        *FeedbackRecord        `json:"feedback,omitempty"`
    Features        map[string]interface{} `json:"features"`
    FeatureNames    []string               `json:"feature_names"`
    AttackType      string                 `json:"attack_type"`
    AttackClass     int                    `json:"attack_class"`
    PerClassScores  map[string]float64     `json:"per_class_scores"`
    AnomalyScore    float64                `json:"anomaly_score,omitempty"`
    AnomalyLevel    string                 `json:"anomaly_level,omitempty"`
    IsZeroDay       bool                   `json:"is_zero_day,omitempty"`
}

type FeedbackRecord struct {
	Reason    string    `json:"reason"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
}

type LogEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	SourceIP      string    `json:"source_ip"`
	DestIP        string    `json:"dest_ip"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	Action        string    `json:"action"`
	Reason        string    `json:"reason"`
	RuleID        string    `json:"rule_id"`
	ConnectionID  string    `json:"connection_id"`
	CountPerMin   int       `json:"count_per_min"`
	AttackType    string    `json:"attack_type"`     // New
	MLConfidence  float64   `json:"ml_confidence"`   // New
}

// Constants
const (
	MaxConnectionsPerMinute = 30
	WarningThreshold        = 15
	BlockDuration           = 2 * time.Minute
	CleanupInterval         = 5 * time.Minute
	MLRuleExpiry            = 24 * time.Hour
	MLCacheExpiry           = 10 * time.Minute
)

// Log reasons
const (
	ReasonRuleMatch     = "RULE_MATCH"
	ReasonIPBlockList   = "IP_BLOCKLIST"
	ReasonIPAllowList   = "IP_ALLOWLIST"
	ReasonDDOSBlock     = "DDOS_PROTECTION"
	ReasonDefaultAllow  = "DEFAULT_ALLOW"
	ReasonMLBlock       = "ML_DETECTION"
	ReasonMLAlert       = "ML_ALERT"
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
	TotalConnections   int
	BlockedConnections int
	AllowedConnections int
	DDosBlocks         int
	RuleMatches        int
	MLBlocks           int               // New
	MLAlerts           int               // New
	StartTime          time.Time
	AttackCounts       map[string]int    // New: Count by attack type
}

// Rule defines a single firewall rule
type Rule struct {
	ID          string
	Type        string
	SourceIP    string
	Destination string
	Port        int
	Protocol    string
	Description string
	CreatedAt   time.Time
	Priority    int
	Enabled     bool
	ExpiresAt   *time.Time
	MLGenerated bool      // New: Flag for ML-generated rules
	AttackType  string    // New: Associated attack type
}

// NewFirewall creates a new enhanced firewall instance
func NewFirewall() *Firewall {
	fw := &Firewall{
		rules:           make([]Rule, 0),
		blockedIPs:      make(map[string]bool),
		allowedIPs:      make(map[string]bool),
		connections:     make(map[string]int),
		connectionRates: make(map[string]*RateTracker),
		stats: &Statistics{
			StartTime:    time.Now(),
			AttackCounts: make(map[string]int),
		},
		history:       make([]*ConnectionRecord, 0),
		nextID:        1,
		attackCounts:  make(map[string]int),
		mlRuleCache:   make(map[string]*MLRuleInfo),
	}

	// Start background cleanup goroutines
	go fw.cleanupRoutine()
	go fw.expiryCleanup()
	go fw.mlRuleCacheCleanup()

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
			if now.Sub(tracker.FirstSeen) > time.Hour && now.After(tracker.BlockedUntil) {
				delete(fw.connectionRates, ip)
			}
		}
		fw.mu.Unlock()
	}
}

// mlRuleCacheCleanup cleans up old ML rule cache entries
func (fw *Firewall) mlRuleCacheCleanup() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		fw.cacheMutex.Lock()
		now := time.Now()
		for ip, info := range fw.mlRuleCache {
			if now.After(info.ExpiresAt) {
				delete(fw.mlRuleCache, ip)
			}
		}
		fw.cacheMutex.Unlock()
	}
}

// AddConnectionToHistory adds a connection record to history
func (fw *Firewall) AddConnectionToHistory(conn *ConnectionRecord) {
	fw.historyLock.Lock()
	defer fw.historyLock.Unlock()

	conn.ID = fw.nextID
	fw.nextID++

	// Update attack counts
	if conn.AttackType != "Normal" {
		fw.attackMutex.Lock()
		fw.attackCounts[conn.AttackType]++
		fw.attackMutex.Unlock()
	}

	fw.history = append(fw.history, conn)

	// Keep last 10000 connections
	if len(fw.history) > 10000 {
		fw.history = fw.history[1:]
	}
}

// AddRule adds a new firewall rule
func (fw *Firewall) AddRule(ruleType, sourceIP, dest, protocol, description string, port int) string {
	return fw.AddRuleWithPriority(ruleType, sourceIP, dest, protocol, description, port, 1)
}

// AddRuleWithPriority adds a new firewall rule with custom priority
func (fw *Firewall) AddRuleWithPriority(ruleType, sourceIP, dest, protocol, description string, port int, priority int) string {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !isValidRuleType(ruleType) {
		return "error: invalid rule type"
	}

	if !isValidProtocol(protocol) {
		return "error: invalid protocol"
	}

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
		MLGenerated: false,
	}

	fw.insertRuleSorted(rule)

	if ruleType == "block" {
		fw.blockedIPs[sourceIP] = true
	} else if ruleType == "allow" {
		fw.allowedIPs[sourceIP] = true
	}

	return rule.ID
}

// AddMLRule adds an ML-generated rule with attack type and expiry
func (fw *Firewall) AddMLRule(ruleType, sourceIP, dest, protocol, description string,
	port, priority int, expiresAfter time.Duration, attackType string, confidence float64) string {

	fw.mu.Lock()
	defer fw.mu.Unlock()

	if !isValidRuleType(ruleType) || !isValidProtocol(protocol) {
		return ""
	}

	var expiresAt *time.Time
	if expiresAfter > 0 {
		t := time.Now().Add(expiresAfter)
		expiresAt = &t
	}

	rule := Rule{
		ID:          fmt.Sprintf("ml-%d-%d", time.Now().UnixNano(), len(fw.rules)+1),
		Type:        ruleType,
		SourceIP:    sourceIP,
		Destination: dest,
		Port:        port,
		Protocol:    protocol,
		Description: fmt.Sprintf("%s attack (conf=%.2f) - %s", attackType, confidence, description),
		CreatedAt:   time.Now(),
		Priority:    priority,
		Enabled:     true,
		ExpiresAt:   expiresAt,
		MLGenerated: true,
		AttackType:  attackType,
	}

	fw.insertRuleSorted(rule)

	if ruleType == "block" {
		fw.blockedIPs[sourceIP] = true

		// Cache the ML rule info
		fw.cacheMutex.Lock()
		fw.mlRuleCache[sourceIP] = &MLRuleInfo{
			RuleID:     rule.ID,
			AttackType: attackType,
			Confidence: confidence,
			ExpiresAt:  time.Now().Add(expiresAfter),
		}
		fw.cacheMutex.Unlock()
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

// expiryCleanup periodically removes expired rules
func (fw *Firewall) expiryCleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		fw.mu.Lock()
		now := time.Now()
		newRules := make([]Rule, 0, len(fw.rules))

		for _, r := range fw.rules {
			if r.ExpiresAt != nil && now.After(*r.ExpiresAt) {
				if r.Type == "block" {
					delete(fw.blockedIPs, r.SourceIP)
				} else if r.Type == "allow" {
					delete(fw.allowedIPs, r.SourceIP)
				}
				continue
			}
			newRules = append(newRules, r)
		}

		fw.rules = newRules
		fw.mu.Unlock()
	}
}

// CheckConnection checks if a connection should be allowed with DDoS protection and ML
func (fw *Firewall) CheckConnection(sourceIP, destIP string, port int, protocol string) bool {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.stats.TotalConnections++

	connectionID := fmt.Sprintf("%s-%d-%s", sourceIP, port, protocol)
	currentCount := fw.updateRateTracker(sourceIP)

	// Create log entry base
	logEntry := LogEntry{
		Timestamp:    time.Now(),
		SourceIP:     sourceIP,
		DestIP:       destIP,
		Port:         port,
		Protocol:     protocol,
		CountPerMin:  currentCount,
		ConnectionID: connectionID,
	}

	// DDoS Protection
	if fw.isRateLimited(sourceIP) {
		fw.stats.BlockedConnections++
		fw.stats.DDosBlocks++

		logEntry.Action = "BLOCK"
		logEntry.Reason = ReasonDDOSBlock
		fw.addLog(logEntry)

		fmt.Printf("🚨 REAL-TIME DDoS BLOCKED: %s -> %s:%d %s (Rate limit exceeded)\n",
			sourceIP, destIP, port, protocol)
		return false
	}

	fw.connections[sourceIP]++

	if currentCount == WarningThreshold {
		fmt.Printf("⚠️  DDoS WARNING: IP %s is making suspicious connections (%d/min)\n",
			sourceIP, currentCount)
	}

	if currentCount >= MaxConnectionsPerMinute {
		fmt.Printf("🔴 CRITICAL: DDoS Attack Detected from %s! Blocking for %v\n",
			sourceIP, BlockDuration)
	}

	// Check quick block list
	if fw.blockedIPs[sourceIP] {
		fw.stats.BlockedConnections++

		logEntry.Action = "BLOCK"
		logEntry.Reason = ReasonIPBlockList
		fw.addLog(logEntry)

		fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (IP in block list)\n",
			sourceIP, destIP, port, protocol)
		return false
	}

	// Check quick allow list
	if fw.allowedIPs[sourceIP] {
		fw.stats.AllowedConnections++

		logEntry.Action = "ALLOW"
		logEntry.Reason = ReasonIPAllowList
		fw.addLog(logEntry)

		fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (IP in allow list)\n",
			sourceIP, destIP, port, protocol)
		return true
	}

	// Check rules in priority order
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

				fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Rule: %s)\n",
					sourceIP, destIP, port, protocol, rule.Description)
				return true
			} else {
				fw.stats.BlockedConnections++

				logEntry.Action = "BLOCK"
				logEntry.Reason = ReasonRuleMatch
				fw.addLog(logEntry)

				fmt.Printf("🚫 BLOCKED: %s -> %s:%d %s (Rule: %s)\n",
					sourceIP, destIP, port, protocol, rule.Description)
				return false
			}
		}
	}

	// Default allow if no rules match
	fw.stats.AllowedConnections++

	logEntry.Action = "ALLOW"
	logEntry.Reason = ReasonDefaultAllow
	fw.addLog(logEntry)

	fmt.Printf("✅ ALLOWED: %s -> %s:%d %s (Default allow)\n",
		sourceIP, destIP, port, protocol)
	return true
}

// ML-Enhanced CheckConnection with 5-class analysis
func (fw *Firewall) CheckConnectionWithML(sourceIP, destIP string, port int, protocol string,
	mlResult *MultiClassScore) (bool, string) {

	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.stats.TotalConnections++

	connectionID := fmt.Sprintf("%s-%d-%s", sourceIP, port, protocol)
	currentCount := fw.updateRateTracker(sourceIP)

	logEntry := LogEntry{
		Timestamp:     time.Now(),
		SourceIP:      sourceIP,
		DestIP:        destIP,
		Port:          port,
		Protocol:      protocol,
		CountPerMin:   currentCount,
		ConnectionID:  connectionID,
		AttackType:    mlResult.PredictedClass,
		MLConfidence:  mlResult.Confidence,
	}

	// DDoS Protection
	if fw.isRateLimited(sourceIP) {
		fw.stats.BlockedConnections++
		fw.stats.DDosBlocks++

		logEntry.Action = "BLOCK"
		logEntry.Reason = ReasonDDOSBlock
		fw.addLog(logEntry)

		return false, ReasonDDOSBlock
	}

	fw.connections[sourceIP]++

	// Check if IP has existing ML rule
	fw.cacheMutex.RLock()
	mlRule, hasMLRule := fw.mlRuleCache[sourceIP]
	fw.cacheMutex.RUnlock()

	if hasMLRule && time.Now().Before(mlRule.ExpiresAt) {
		fw.stats.BlockedConnections++
		fw.stats.MLBlocks++

		logEntry.Action = "BLOCK"
		logEntry.Reason = ReasonMLBlock
		logEntry.RuleID = mlRule.RuleID
		fw.addLog(logEntry)

		fmt.Printf("🤖 ML BLOCKED: %s -> %s:%d %s (%s attack, conf=%.2f)\n",
			sourceIP, destIP, port, protocol, mlRule.AttackType, mlRule.Confidence)
		return false, ReasonMLBlock
	}

	// Check quick block list
	if fw.blockedIPs[sourceIP] {
		fw.stats.BlockedConnections++

		logEntry.Action = "BLOCK"
		logEntry.Reason = ReasonIPBlockList
		fw.addLog(logEntry)

		return false, ReasonIPBlockList
	}

	// Check quick allow list
	if fw.allowedIPs[sourceIP] {
		fw.stats.AllowedConnections++

		logEntry.Action = "ALLOW"
		logEntry.Reason = ReasonIPAllowList
		fw.addLog(logEntry)

		return true, ReasonIPAllowList
	}

	// Check rules
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
				return true, ReasonRuleMatch
			} else {
				fw.stats.BlockedConnections++
				logEntry.Action = "BLOCK"
				logEntry.Reason = ReasonRuleMatch
				fw.addLog(logEntry)
				return false, ReasonRuleMatch
			}
		}
	}

	// ML-based decision if attack detected
	if mlResult.IsMalicious {
		// Determine action based on attack type and confidence
		var shouldBlock bool
		var reason string

		switch mlResult.PredictedClass {
		case "U2R":
			shouldBlock = mlResult.Confidence >= 0.6 // U2R is critical
			reason = "U2R_ATTACK"
		case "DoS":
			shouldBlock = mlResult.Confidence >= 0.7
			reason = "DOS_ATTACK"
		case "R2L":
			shouldBlock = mlResult.Confidence >= 0.75
			reason = "R2L_ATTACK"
		case "Probe":
			shouldBlock = mlResult.Confidence >= 0.8
			reason = "PROBE_SCAN"
		default:
			shouldBlock = false
			reason = "UNKNOWN"
		}

		if shouldBlock {
			fw.stats.BlockedConnections++
			fw.stats.MLBlocks++

			logEntry.Action = "BLOCK"
			logEntry.Reason = ReasonMLBlock
			fw.addLog(logEntry)

			// Auto-create ML rule for future blocks
			if mlResult.Confidence >= 0.85 {
				go fw.AutoCreateMLRule(sourceIP, mlResult.PredictedClass, mlResult.Confidence)
			}

			fmt.Printf("🤖 ML DETECTED & BLOCKED: %s %s attack from %s (conf=%.2f)\n",
				mlResult.PredictedClass, reason, sourceIP, mlResult.Confidence)
			return false, ReasonMLBlock
		} else {
			fw.stats.MLAlerts++
			logEntry.Action = "ALLOW"
			logEntry.Reason = ReasonMLAlert
			fw.addLog(logEntry)

			fmt.Printf("⚠️  ML ALERT: %s %s attack from %s (conf=%.2f) - monitoring\n",
				mlResult.PredictedClass, reason, sourceIP, mlResult.Confidence)
			return true, ReasonMLAlert
		}
	}

	// Default allow
	fw.stats.AllowedConnections++
	logEntry.Action = "ALLOW"
	logEntry.Reason = ReasonDefaultAllow
	fw.addLog(logEntry)

	return true, ReasonDefaultAllow
}

// AutoCreateMLRule automatically creates a temporary block rule for malicious IPs
func (fw *Firewall) AutoCreateMLRule(ip, attackType string, confidence float64) {
	// Calculate priority based on attack type and confidence
	priority := 50
	switch attackType {
	case "U2R":
		priority = 100
	case "DoS":
		priority = 80
	case "R2L":
		priority = 70
	case "Probe":
		priority = 60
	}

	// Adjust by confidence
	priority = priority + int(confidence*20)
	if priority > 100 {
		priority = 100
	}

	// Set expiry based on attack type
	expiry := MLRuleExpiry
	if attackType == "Probe" {
		expiry = 6 * time.Hour
	}

	description := fmt.Sprintf("Auto-blocked by ML (%s attack)", attackType)

	fw.AddMLRule("block", ip, "any", "any", description, 0, priority, expiry, attackType, confidence)
}

// updateRateTracker updates connection rate for an IP
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
	}

	// Reset if minute has passed
	if time.Since(tracker.LastReset) > time.Minute {
		tracker.Count = 1
		tracker.LastReset = time.Now()
	} else {
		tracker.Count++
	}
	return tracker.Count
}

// isRateLimited checks if an IP has exceeded connection rate limits
func (fw *Firewall) isRateLimited(ip string) bool {
	tracker, exists := fw.connectionRates[ip]
	if !exists {
		return false
	}

	if time.Now().Before(tracker.BlockedUntil) {
		return true
	}

	if tracker.Count >= MaxConnectionsPerMinute {
		tracker.BlockedUntil = time.Now().Add(BlockDuration)
		return true
	}

	return false
}

// matchRule checks if a connection matches a specific rule
func (fw *Firewall) matchRule(rule Rule, sourceIP, destIP string, port int, protocol string) bool {
	if rule.SourceIP != "any" && !fw.matchIP(rule.SourceIP, sourceIP) {
		return false
	}

	if rule.Destination != "any" && !fw.matchIP(rule.Destination, destIP) {
		return false
	}

	if rule.Port != 0 && rule.Port != port {
		return false
	}

	if rule.Protocol != "any" && !strings.EqualFold(rule.Protocol, protocol) {
		return false
	}

	return true
}

// matchIP checks if an IP matches a CIDR or exact IP
func (fw *Firewall) matchIP(cidrOrIP, ip string) bool {
	if cidrOrIP == ip {
		return true
	}

	_, ipnet, err := net.ParseCIDR(cidrOrIP)
	if err == nil {
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			return ipnet.Contains(parsedIP)
		}
	}

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
			if rule.Type == "block" {
				delete(fw.blockedIPs, rule.SourceIP)

				// Remove from ML cache if it's an ML rule
				if rule.MLGenerated {
					fw.cacheMutex.Lock()
					delete(fw.mlRuleCache, rule.SourceIP)
					fw.cacheMutex.Unlock()
				}
			} else if rule.Type == "allow" {
				delete(fw.allowedIPs, rule.SourceIP)
			}

			fw.rules = append(fw.rules[:i], fw.rules[i+1:]...)
			return true
		}
	}
	return false
}

// EnableRule enables/disables a rule
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
	stats["ml_blocks"] = fw.stats.MLBlocks
	stats["ml_alerts"] = fw.stats.MLAlerts
	stats["tracked_ips"] = len(fw.connectionRates)
	stats["ml_rules"] = fw.countMLRules()
	stats["uptime_seconds"] = int(time.Since(fw.stats.StartTime).Seconds())

	return stats
}

// countMLRules counts ML-generated rules
func (fw *Firewall) countMLRules() int {
	count := 0
	for _, rule := range fw.rules {
		if rule.MLGenerated {
			count++
		}
	}
	return count
}

// GetAttackStats returns attack type statistics
func (fw *Firewall) GetAttackStats() map[string]interface{} {
	fw.attackMutex.RLock()
	defer fw.attackMutex.RUnlock()

	stats := make(map[string]interface{})
	total := 0

	for attackType, count := range fw.attackCounts {
		stats[attackType] = count
		total += count
	}

	stats["total_attacks"] = total

	// Calculate percentages
	if total > 0 {
		percentages := make(map[string]float64)
		for attackType, count := range fw.attackCounts {
			percentages[attackType] = float64(count) / float64(total) * 100
		}
		stats["percentages"] = percentages
	}

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

// ShowActiveAttacks displays currently active attacks
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

	// Show ML-blocked IPs
	fw.cacheMutex.RLock()
	mlBlocked := 0
	for ip, info := range fw.mlRuleCache {
		if now.Before(info.ExpiresAt) {
			mlBlocked++
			remaining := time.Until(info.ExpiresAt).Round(time.Minute)
			fmt.Printf("🤖 IP: %s | ML Blocked (%s) | Expires in: %v\n",
				ip, info.AttackType, remaining)
		}
	}
	fw.cacheMutex.RUnlock()

	if mlBlocked > 0 {
		fmt.Printf("🤖 %d IPs blocked by ML\n", mlBlocked)
	}
}

// addLog adds a log entry
func (fw *Firewall) addLog(entry LogEntry) {
	fw.logMutex.Lock()
	defer fw.logMutex.Unlock()

	fw.logs = append(fw.logs, entry)

	if len(fw.logs) > 1000 {
		fw.logs = fw.logs[1:]
	}
}

// GetLogs returns recent logs
func (fw *Firewall) GetLogs(limit int) []LogEntry {
	fw.logMutex.RLock()
	defer fw.logMutex.RUnlock()

	if limit <= 0 || limit > len(fw.logs) {
		limit = len(fw.logs)
	}
	return fw.logs[len(fw.logs)-limit:]
}

// SearchLogsByIP searches logs by IP
func (fw *Firewall) SearchLogsByIP(ip string) []LogEntry {
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

// GetLogStats returns log statistics
func (fw *Firewall) GetLogStats() map[string]int {
	fw.logMutex.RLock()
	defer fw.logMutex.RUnlock()

	stats := make(map[string]int)
	stats["total_logs"] = len(fw.logs)

	allowed := 0
	blocked := 0
	mlBlocks := 0
	attackCounts := make(map[string]int)

	for _, log := range fw.logs {
		if log.Action == "ALLOW" {
			allowed++
		} else {
			blocked++
			if log.Reason == ReasonMLBlock {
				mlBlocks++
			}
		}
		if log.AttackType != "" && log.AttackType != "Normal" {
			attackCounts[log.AttackType]++
		}
	}

	stats["allowed_logs"] = allowed
	stats["blocked_logs"] = blocked
	stats["ml_blocks"] = mlBlocks

	// Add attack type counts
	for at, count := range attackCounts {
		stats["attack_"+at] = count
	}

	return stats
}

// GetHistory returns connection history
func (fw *Firewall) GetHistory(limit int) []*ConnectionRecord {
	fw.historyLock.RLock()
	defer fw.historyLock.RUnlock()

	if limit <= 0 || limit > len(fw.history) {
		limit = len(fw.history)
	}
	return fw.history[len(fw.history)-limit:]
}

// SearchHistoryByIP searches history by IP
func (fw *Firewall) SearchHistoryByIP(ip string) []*ConnectionRecord {
	fw.historyLock.RLock()
	defer fw.historyLock.RUnlock()

	var results []*ConnectionRecord
	for _, record := range fw.history {
		if record.SourceIP == ip || record.DestIP == ip {
			results = append(results, record)
		}
	}
	return results
}

// GetAttackHistory returns attack history by type
func (fw *Firewall) GetAttackHistory(attackType string) []*ConnectionRecord {
	fw.historyLock.RLock()
	defer fw.historyLock.RUnlock()

	var results []*ConnectionRecord
	for _, record := range fw.history {
		if record.AttackType == attackType {
			results = append(results, record)
		}
	}
	return results
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

// mapKeys helper
func (fw *Firewall) mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mapToSlice helper
func (fw *Firewall) mapToSlice(s []string) map[string]bool {
	m := make(map[string]bool)
	for _, v := range s {
		m[v] = true
	}
	return m
}
