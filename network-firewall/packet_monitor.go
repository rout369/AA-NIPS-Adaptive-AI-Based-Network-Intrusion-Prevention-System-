package main

import (
	"fmt"
	"net"
	"bufio"
    "os"
    "strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ConnectionStats struct {
	PacketCount   int
	ByteCount     int
	BytesSent     int
	BytesReceived int
	FirstSeen     time.Time
	LastSeen      time.Time
	Protocol      string
}

type EnhancedPacketMonitor struct {
	handle      *pcap.Handle
	device      string
	uniqueIPs   map[string]bool
	connections map[string]*ConnectionStats
	mutex       sync.RWMutex
	startTime   time.Time
	firewall    *Firewall
	flowCache   map[string]*FlowInfo
	cacheMutex  sync.RWMutex
}

type FlowInfo struct {
	SrcIP              string
	DstIP              string
	SrcPort            int
	DstPort            int
	Protocol           string
	LastMLScore        float64
	ConsensusPercentage float64
	ConsensusLevel     string
	ModelScores        map[string]float64
	LastChecked        time.Time
	ExpiresAt          time.Time
	MultiClassResult   *MultiClassScore
	AttackType         string
	AttackClass        int
	PerClassScores     map[string]float64
}

func NewEnhancedPacketMonitor(device string, firewall *Firewall) *EnhancedPacketMonitor {
	return &EnhancedPacketMonitor{
		device:      device,
		uniqueIPs:   make(map[string]bool),
		connections: make(map[string]*ConnectionStats),
		startTime:   time.Now(),
		firewall:    firewall,
		flowCache:   make(map[string]*FlowInfo),
	}
}

func (epm *EnhancedPacketMonitor) Start() error {
	var err error

	epm.handle, err = pcap.OpenLive(epm.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer epm.handle.Close()

	err = epm.handle.SetBPFFilter("tcp or udp or icmp or icmp6")
	if err != nil {
		return err
	}

	fmt.Printf("🎯 Enhanced packet monitor started on %s\n", epm.getInterfaceName(epm.device))
	fmt.Println("📊 Live packet display active with 5-class ML analysis...")
	fmt.Println("🛑 Press Ctrl+C to stop and show statistics")
	fmt.Println(strings.Repeat("─", 80))

	go epm.printStatistics()
	go epm.cacheCleanupRoutine()

	packetSource := gopacket.NewPacketSource(epm.handle, epm.handle.LinkType())
	for packet := range packetSource.Packets() {
		epm.processEnhancedPacket(packet)

		epm.processPacketAnomaly(packet)

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

func (epm *EnhancedPacketMonitor) Stop() {
	fmt.Println("\n\n⏸️  Stopping packet monitor...")
	if epm.handle != nil {
		epm.handle.Close()
	}
}

func (epm *EnhancedPacketMonitor) processEnhancedPacket(packet gopacket.Packet) {
    epm.mutex.Lock()
    defer epm.mutex.Unlock()

    networkLayer := packet.NetworkLayer()
    if networkLayer == nil {
        return
    }

    var srcIP, dstIP net.IP
    var protocol string

    switch ipLayer := networkLayer.(type) {
    case *layers.IPv4:
        srcIP = ipLayer.SrcIP
        dstIP = ipLayer.DstIP
        protocol = "IPv4"
    case *layers.IPv6:
        srcIP = ipLayer.SrcIP
        dstIP = ipLayer.DstIP
        protocol = "IPv6"
    default:
        return
    }

    srcIPStr := srcIP.String()
    dstIPStr := dstIP.String()

    if !epm.uniqueIPs[srcIPStr] {
        epm.uniqueIPs[srcIPStr] = true
        fmt.Printf("🆕 NEW IP DETECTED: %s\n", srcIPStr)
    }
    if !epm.uniqueIPs[dstIPStr] {
        epm.uniqueIPs[dstIPStr] = true
        fmt.Printf("🆕 NEW IP DETECTED: %s\n", dstIPStr)
    }

    transportLayer := packet.TransportLayer()
    var srcPort, dstPort int
    var transportProtocol string

    if transportLayer != nil {
        switch layer := transportLayer.(type) {
        case *layers.TCP:
            srcPort = int(layer.SrcPort)
            dstPort = int(layer.DstPort)
            transportProtocol = "tcp"
        case *layers.UDP:
            srcPort = int(layer.SrcPort)
            dstPort = int(layer.DstPort)
            transportProtocol = "udp"
        }
    } else {
        switch layer := networkLayer.(type) {
        case *layers.IPv4:
            if layer.Protocol == layers.IPProtocolICMPv4 {
                transportProtocol = "icmp"
            }
        case *layers.IPv6:
            if layer.NextHeader == layers.IPProtocolICMPv6 {
                transportProtocol = "icmp"
            }
        }
    }

    // Update connection stats
    forwardKey := fmt.Sprintf("%s->%s", srcIPStr, dstIPStr)

    if stats, exists := epm.connections[forwardKey]; exists {
        stats.PacketCount++
        stats.ByteCount += len(packet.Data())
        stats.BytesSent += len(packet.Data())
        stats.LastSeen = time.Now()
    } else {
        epm.connections[forwardKey] = &ConnectionStats{
            PacketCount:    1,
            ByteCount:      len(packet.Data()),
            BytesSent:      len(packet.Data()),
            BytesReceived:  0,
            FirstSeen:      time.Now(),
            LastSeen:       time.Now(),
            Protocol:       protocol,
        }
        fmt.Printf("🔗 NEW CONNECTION: %s → %s\n", srcIPStr, dstIPStr)
    }

    // 5-CLASS ML ANALYSIS ONLY - NO ANOMALY HERE
    if epm.firewall != nil && epm.firewall.mlEnabled && transportProtocol != "" {
        
        fmt.Printf("\n%s 5-CLASS ML ANALYSIS %s\n",
            strings.Repeat("─", 25), strings.Repeat("─", 25))
        fmt.Printf("📍 Flow: %s:%d → %s:%d %s\n", srcIPStr, srcPort, dstIPStr, dstPort, transportProtocol)
        
        // Get 5-class scores only
        multiClassScore, multiErr := epm.getMultiClassScore(srcIPStr, dstIPStr, srcPort, dstPort,
            transportProtocol, len(packet.Data()))
        
        // Display 5-class results
        if multiErr != nil {
            fmt.Printf("⚠️ Multi-class ML failed: %v\n", multiErr)
        } else if multiClassScore != nil {
            epm.displayMultiClassAnalysis(srcIPStr, dstIPStr, srcPort, dstPort, 
                transportProtocol, multiClassScore)
        }
        
        // Firewall decision
        if multiErr == nil && multiClassScore != nil {
            allowed, reason := epm.firewall.CheckConnectionWithML(srcIPStr, dstIPStr,
                dstPort, transportProtocol, multiClassScore)
            
            if allowed {
                fmt.Printf("\n🛡️  Firewall: ALLOW (%s)\n", reason)
            } else {
                fmt.Printf("\n🛡️  Firewall: BLOCK (%s)\n", reason)
            }
        }
        
        fmt.Println(strings.Repeat("─", 70))
    }

    // Display live packet info
    appLayer := packet.ApplicationLayer()
    epm.displayLivePacketInfo(packet, srcIPStr, dstIPStr, protocol, transportLayer, appLayer)
}



// New separate function for anomaly detection only
func (epm *EnhancedPacketMonitor) processPacketAnomaly(packet gopacket.Packet) {
    epm.mutex.Lock()
    defer epm.mutex.Unlock()

    networkLayer := packet.NetworkLayer()
    if networkLayer == nil {
        return
    }

    var srcIP, dstIP net.IP
    var networkProtocol string  // Renamed to be clear this is network layer protocol

    switch ipLayer := networkLayer.(type) {
    case *layers.IPv4:
        srcIP = ipLayer.SrcIP
        dstIP = ipLayer.DstIP
        networkProtocol = "IPv4"
    case *layers.IPv6:
        srcIP = ipLayer.SrcIP
        dstIP = ipLayer.DstIP
        networkProtocol = "IPv6"
    default:
        return
    }

    srcIPStr := srcIP.String()
    dstIPStr := dstIP.String()

    transportLayer := packet.TransportLayer()
    var srcPort, dstPort int
    var transportProtocol string

    if transportLayer != nil {
        switch layer := transportLayer.(type) {
        case *layers.TCP:
            srcPort = int(layer.SrcPort)
            dstPort = int(layer.DstPort)
            transportProtocol = "tcp"
        case *layers.UDP:
            srcPort = int(layer.SrcPort)
            dstPort = int(layer.DstPort)
            transportProtocol = "udp"
        }
    }

    // Only process if we have transport protocol and ML enabled
    if epm.firewall == nil || !epm.firewall.mlEnabled || transportProtocol == "" {
        return
    }

    // Get connection stats for feature extraction
    forwardKey := fmt.Sprintf("%s->%s", srcIPStr, dstIPStr)
    reverseKey := fmt.Sprintf("%s->%s", dstIPStr, srcIPStr)
    
    // Update or create connection stats for this flow
    if stats, exists := epm.connections[forwardKey]; exists {
        stats.PacketCount++
        stats.BytesSent += len(packet.Data())
        stats.LastSeen = time.Now()
    } else {
        epm.connections[forwardKey] = &ConnectionStats{
            PacketCount: 1,
            BytesSent:   len(packet.Data()),
            FirstSeen:   time.Now(),
            LastSeen:    time.Now(),
            Protocol:    networkProtocol,  // Now using networkProtocol here
        }
    }
    
    // Update reverse connection stats
    if stats, exists := epm.connections[reverseKey]; exists {
        stats.BytesReceived += len(packet.Data())
    } else {
        epm.connections[reverseKey] = &ConnectionStats{
            PacketCount:    0,
            BytesReceived:  len(packet.Data()),
            FirstSeen:      time.Now(),
            LastSeen:       time.Now(),
            Protocol:       networkProtocol,  // Now using networkProtocol here
        }
    }
    
    // Get current stats for feature calculation
    currentStats := epm.connections[forwardKey]
    
    // Calculate features for autoencoder
    duration := time.Since(currentStats.FirstSeen).Seconds()
    if duration < 0.001 {
        duration = 0.001
    }
    
    totalFwdPackets := currentStats.PacketCount
    totalBackwardPackets := 0
    if revStats, hasReverse := epm.connections[reverseKey]; hasReverse {
        totalBackwardPackets = revStats.PacketCount
    }
    
    fwdPacketLengthMean := float64(currentStats.BytesSent) / float64(totalFwdPackets)
    if fwdPacketLengthMean < 1 {
        fwdPacketLengthMean = float64(len(packet.Data()))
    }
    
    flowBytesPerSec := float64(currentStats.BytesSent) / duration
    flowPacketsPerSec := float64(totalFwdPackets) / duration
    
    // Create features map for autoencoder only
    features := make(map[string]interface{})
    features["Destination_Port"] = dstPort
    features["Flow_Duration"] = duration * 1000000
    features["Total_Fwd_Packets"] = totalFwdPackets
    features["Total_Backward_Packets"] = totalBackwardPackets
    features["Fwd_Packet_Length_Mean"] = fwdPacketLengthMean
    features["Flow_Bytes_s"] = flowBytesPerSec
    features["Flow_Packets_s"] = flowPacketsPerSec
    features["Init_Win_bytes_forward"] = 65535
    features["Init_Win_bytes_backward"] = 65535
    
    // Show anomaly detection header with network protocol info
    fmt.Printf("\n%s ZERO-DAY ANOMALY DETECTION [%s] %s\n",
        strings.Repeat("═", 15), networkProtocol, strings.Repeat("═", 15))
    fmt.Printf("📍 Flow: %s:%d → %s:%d %s\n", srcIPStr, srcPort, dstIPStr, dstPort, transportProtocol)
    
    // Get anomaly score
    anomalyScore, anomalyErr := epm.firewall.mlClient.GetAnomalyScore(features)
    
    // Display anomaly results
    if anomalyErr != nil {
        fmt.Printf("❌ Anomaly detection failed: %v\n", anomalyErr)
    } else if anomalyScore != nil {
        anomalyColor := "⚪"
        if anomalyScore.AnomalyLevel == "suspicious" {
            anomalyColor = "🟡"
        } else if anomalyScore.AnomalyLevel == "critical" {
            anomalyColor = "🔴"
        }
        
        fmt.Printf("   • Reconstruction Error: %.4f %s\n", 
            anomalyScore.AnomalyScore, anomalyColor)
        fmt.Printf("   • Status: %s\n", anomalyScore.AnomalyLevel)
        
        if anomalyScore.IsAnomaly {
            fmt.Printf("   • 🚨 ZERO-DAY CANDIDATE!\n")
            if anomalyScore.AnomalyLevel == "critical" {
                fmt.Printf("   • ⚠️  Highly anomalous - Unknown attack pattern\n")
            }
        }
        
        fmt.Printf("   • Threshold: %.4f\n", anomalyScore.Threshold)
    }
    
    fmt.Println(strings.Repeat("═", 60))
}


func (epm *EnhancedPacketMonitor) displayMultiClassAnalysis(srcIP, dstIP string,
	srcPort, dstPort int, protocol string, score *MultiClassScore) {

	fmt.Printf("📍 Flow: %s:%d → %s:%d %s\n", srcIP, srcPort, dstIP, dstPort, protocol)

	fmt.Println("\n🔍 ATTACK PROBABILITIES:")
	classOrder := []string{"Normal", "DoS", "Probe", "R2L", "U2R"}
	classColors := map[string]string{
		"Normal": "⚪",
		"DoS":    "🔴",
		"Probe":  "🟠",
		"R2L":    "🟡",
		"U2R":    "🟣",
	}

	for _, class := range classOrder {
		if prob, exists := score.ThreatScores[class]; exists {
			color := classColors[class]
			bar := getProbabilityBar(prob)
			fmt.Printf("   %s %-8s: %5.1f%% %s\n", color, class, prob*100, bar)
		}
	}

	fmt.Printf("\n🎯 PREDICTION: %s %s (%.1f%% confidence)\n",
		classColors[score.PredictedClass], score.PredictedClass, score.Confidence*100)

	switch score.PredictedClass {
	case "U2R":
		fmt.Printf("   🚨 CRITICAL: User to Root attack! Isolate host immediately!\n")
	case "DoS":
		fmt.Printf("   🔴 WARNING: DoS attack detected! Rate limiting recommended.\n")
	case "R2L":
		fmt.Printf("   🟡 ALERT: Remote access attempt! Monitor credentials.\n")
	case "Probe":
		fmt.Printf("   🟠 NOTICE: Network scanning detected! Intelligence gathering.\n")
	}

	fmt.Printf("   Consensus: %.1f%% (%s agreement)\n",
		score.ConsensusPercentage, score.ConsensusLevel)

 	// Show top 3 models for brevity
    if len(score.ModelScores) > 0 {
        fmt.Println("\n🤖 Top Model Predictions:")
        displayNames := map[string]string{
            "random_forest":  "Random Forest",
            "gradient_boosting": "Gradient Boost",
            "xgboost":        "XGBoost",
            "neural_network": "Neural Net",
        }

        count := 0
        for model, displayName := range displayNames {
            if count >= 3 {
                break
            }
            if modelScores, exists := score.ModelScores[model]; exists {
                fmt.Printf("   • %-14s: ", displayName)
                // Show only top 2 classes for each model
                type classProb struct {
                    class string
                    prob  float64
                }
                probs := []classProb{}
                for class, prob := range modelScores {
                    probs = append(probs, classProb{class, prob})
                }
                // Sort by probability (simple bubble sort)
                for i := 0; i < len(probs)-1; i++ {
                    for j := i + 1; j < len(probs); j++ {
                        if probs[i].prob < probs[j].prob {
                            probs[i], probs[j] = probs[j], probs[i]
                        }
                    }
                }
                // Show top 2
                for i := 0; i < 2 && i < len(probs); i++ {
                    color := classColors[probs[i].class]
                    fmt.Printf("%s%s:%.0f%% ", color, probs[i].class[:2], probs[i].prob*100)
                }
                fmt.Println()
                count++
            }
        }
        if count < len(score.ModelScores) {
            fmt.Printf("   • ... and %d more models\n", len(score.ModelScores)-count)
        }
    }
}

func (epm *EnhancedPacketMonitor) displayLivePacketInfo(packet gopacket.Packet,
	srcIP, dstIP, protocol string, transportLayer gopacket.TransportLayer,
	appLayer gopacket.ApplicationLayer) {

	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
	var info strings.Builder

	info.WriteString(fmt.Sprintf("🕒 [%s] ", timestamp))
	info.WriteString(fmt.Sprintf("🌐 %s %s → %s", protocol, srcIP, dstIP))

	if transportLayer != nil {
		switch layer := transportLayer.(type) {
		case *layers.TCP:
			info.WriteString(fmt.Sprintf(" | 🚦 TCP %d→%d", layer.SrcPort, layer.DstPort))
			info.WriteString(fmt.Sprintf(" | 🚩 %s", epm.getTCPFlags(layer)))
		case *layers.UDP:
			info.WriteString(fmt.Sprintf(" | 🚦 UDP %d→%d", layer.SrcPort, layer.DstPort))
			info.WriteString(fmt.Sprintf(" | 📏 Len:%d", layer.Length))
		}
	}

	if appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			info.WriteString(fmt.Sprintf(" | 📦 %d bytes", len(payload)))
		}
	}

	info.WriteString(fmt.Sprintf(" | 💾 Size:%d bytes", len(packet.Data())))
	fmt.Println(info.String())
}

func (epm *EnhancedPacketMonitor) getTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "S"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.FIN {
		flags += "F"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.URG {
		flags += "U"
	}
	if flags == "" {
		flags = "-"
	}
	return flags
}

func (epm *EnhancedPacketMonitor) printStatistics() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		epm.mutex.RLock()
		fmt.Printf("\n%s STATISTICS UPDATE %s\n",
			strings.Repeat("▀", 30), strings.Repeat("▀", 30))
		fmt.Printf("🕒 Uptime: %s\n", time.Since(epm.startTime).Round(time.Second))
		fmt.Printf("🌐 Unique IPs: %d\n", len(epm.uniqueIPs))
		fmt.Printf("🔗 Active connections: %d\n", len(epm.connections))

		if epm.firewall != nil {
			fwStats := epm.firewall.GetStats()
			fmt.Printf("🛡️  Firewall: %d allowed, %d blocked, %d ML blocks\n",
				fwStats["allowed_connections"],
				fwStats["blocked_connections"],
				fwStats["ml_blocks"])

			attackStats := epm.firewall.GetAttackStats()
			if total, ok := attackStats["total_attacks"]; ok && total.(int) > 0 {
				fmt.Printf("🎯 Attack types: ")
				for _, at := range []string{"DoS", "Probe", "R2L", "U2R"} {
					if count, exists := attackStats[at]; exists {
						fmt.Printf("%s:%d ", at, count)
					}
				}
				fmt.Println()
			}
		}

		fmt.Printf("📦 Top connections:\n")
		topConnections := 0
		for conn, stats := range epm.connections {
			if topConnections >= 5 {
				break
			}
			fmt.Printf("   %s: %d packets, %d bytes\n",
				conn, stats.PacketCount, stats.ByteCount)
			topConnections++
		}
		fmt.Printf("%s\n\n", strings.Repeat("▄", 80))
		epm.mutex.RUnlock()
	}
}

func (epm *EnhancedPacketMonitor) getInterfaceName(device string) string {
	cleanName := strings.TrimPrefix(device, `\Device\NPF_`)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return device
	}

	for _, dev := range devices {
		if dev.Name == device {
			if len(dev.Description) > 0 {
				return dev.Description
			}
			for _, addr := range dev.Addresses {
				if addr.IP.IsLoopback() {
					return "Loopback Adapter"
				}
				if strings.Contains(dev.Description, "Wireless") ||
					strings.Contains(dev.Name, "Wi-Fi") {
					return "Wi-Fi Adapter"
				}
				if strings.Contains(dev.Description, "Ethernet") {
					return "Ethernet Adapter"
				}
			}
		}
	}
	return cleanName
}

func (epm *EnhancedPacketMonitor) extractMLFeatures(srcIP, dstIP string,
    srcPort, dstPort int, protocol string, packetLen int) map[string]interface{} {

    features := make(map[string]interface{})

    protocolNum := 0
    switch strings.ToLower(protocol) {
    case "tcp":
        protocolNum = 6
    case "udp":
        protocolNum = 17
    case "icmp":
        protocolNum = 1
    }

    forwardKey := fmt.Sprintf("%s->%s", srcIP, dstIP)
    reverseKey := fmt.Sprintf("%s->%s", dstIP, srcIP)

    // Initialize variables with default values
    packetCount := 1
    bytesSent := packetLen
    bytesReceived := 0
    duration := 0.1
    totalFwdPackets := 1
    totalBackwardPackets := 0
    fwdPacketLengthMean := float64(packetLen)
    flowBytesPerSec := float64(packetLen) / duration
    flowPacketsPerSec := 1.0 / duration
    
    // Default window sizes (common values)
    initWinBytesForward := 65535  // Default TCP window size
    initWinBytesBackward := 65535 // Default TCP window size

    // Get connection stats if they exist
    if stats, exists := epm.connections[forwardKey]; exists {
        packetCount = stats.PacketCount
        bytesSent = stats.BytesSent
        duration = time.Since(stats.FirstSeen).Seconds()
        if duration < 0.001 {
            duration = 0.001 // Avoid division by zero
        }
        totalFwdPackets = stats.PacketCount
        fwdPacketLengthMean = float64(stats.BytesSent) / float64(stats.PacketCount)
        flowBytesPerSec = float64(stats.BytesSent) / duration
        flowPacketsPerSec = float64(stats.PacketCount) / duration
        
        // Try to extract window size from TCP packets (if available)
        // For now, keep default values
    }

    if stats, exists := epm.connections[reverseKey]; exists {
        totalBackwardPackets = stats.PacketCount
        bytesReceived = stats.BytesReceived
    }

    // NSL-KDD 41 features (for 5-class classification)
    features["duration"] = duration
    features["protocol_type"] = protocolNum
    features["service"] = epm.mapPortToService(dstPort)
    features["flag"] = 0
    features["src_bytes"] = bytesSent
    features["dst_bytes"] = bytesReceived
    features["land"] = 0
    features["wrong_fragment"] = 0
    features["urgent"] = 0
    features["hot"] = 0
    features["num_failed_logins"] = 0
    features["logged_in"] = 1
    features["num_compromised"] = 0
    features["root_shell"] = 0
    features["su_attempted"] = 0
    features["num_root"] = 0
    features["num_file_creations"] = 0
    features["num_shells"] = 0
    features["num_access_files"] = 0
    features["num_outbound_cmds"] = 0
    features["is_host_login"] = 0
    features["is_guest_login"] = 0
    features["count"] = packetCount
    features["srv_count"] = packetCount
    features["serror_rate"] = 0.0
    features["srv_serror_rate"] = 0.0
    features["rerror_rate"] = 0.0
    features["srv_rerror_rate"] = 0.0
    features["same_srv_rate"] = 1.0
    features["diff_srv_rate"] = 0.0
    features["srv_diff_host_rate"] = 0.0
    features["dst_host_count"] = packetCount
    features["dst_host_srv_count"] = packetCount
    features["dst_host_same_srv_rate"] = 1.0
    features["dst_host_diff_srv_rate"] = 0.0
    features["dst_host_same_src_port_rate"] = 1.0
    features["dst_host_srv_diff_host_rate"] = 0.0
    features["dst_host_serror_rate"] = 0.0
    features["dst_host_srv_serror_rate"] = 0.0
    features["dst_host_rerror_rate"] = 0.0
    features["dst_host_srv_rerror_rate"] = 0.0

    // Add autoencoder-specific features (for zero-day detection)
    features["Destination_Port"] = dstPort
    features["Flow_Duration"] = duration * 1e6 // Convert to microseconds
    features["Total_Fwd_Packets"] = totalFwdPackets
    features["Total_Backward_Packets"] = totalBackwardPackets
    features["Fwd_Packet_Length_Mean"] = fwdPacketLengthMean
    features["Flow_Bytes_s"] = flowBytesPerSec
    features["Flow_Packets_s"] = flowPacketsPerSec
    features["Init_Win_bytes_forward"] = initWinBytesForward
    features["Init_Win_bytes_backward"] = initWinBytesBackward

    return features
}

func (epm *EnhancedPacketMonitor) mapPortToService(port int) int {
	// Map common ports to service numbers (from NSL-KDD)
	serviceMap := map[int]int{
		80:   1,  // http
		443:  2,  // https
		21:   3,  // ftp
		22:   4,  // ssh
		23:   5,  // telnet
		25:   6,  // smtp
		53:   7,  // dns
		110:  8,  // pop3
		143:  9,  // imap
		161:  10, // snmp
		162:  11, // snmptrap
		123:  12, // ntp
		179:  13, // bgp
		520:  14, // rip
		67:   15, // dhcp
		68:   16, // dhcp
		69:   17, // tftp
		137:  18, // netbios-ns
		138:  19, // netbios-dgm
		139:  20, // netbios-ssn
		445:  21, // microsoft-ds
		514:  22, // syslog
		636:  23, // ldaps
		993:  24, // imaps
		995:  25, // pop3s
		3306: 26, // mysql
		5432: 27, // postgresql
		6379: 28, // redis
		27017:29, // mongodb
	}
	if val, exists := serviceMap[port]; exists {
		return val
	}
	return 0 // unknown service
}

func (epm *EnhancedPacketMonitor) getMultiClassScore(srcIP, dstIP string,
	srcPort, dstPort int, protocol string, packetLen int) (*MultiClassScore, error) {

	flowKey := fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, protocol)

	epm.cacheMutex.RLock()
	cached, exists := epm.flowCache[flowKey]
	epm.cacheMutex.RUnlock()

	now := time.Now()

	if exists && now.Before(cached.ExpiresAt) && cached.MultiClassResult != nil {
		return cached.MultiClassResult, nil
	}

	if epm.firewall == nil || epm.firewall.mlClient == nil || !epm.firewall.mlEnabled {
		return nil, fmt.Errorf("ML not enabled")
	}

	features := epm.extractMLFeatures(srcIP, dstIP, srcPort, dstPort, protocol, packetLen)

	resultChan := make(chan *MultiClassScore, 1)
	errorChan := make(chan error, 1)

	go func() {
		score, err := epm.firewall.mlClient.MultiClassScore(features)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- score
	}()

	select {
	case multiScore := <-resultChan:
		epm.cacheMutex.Lock()
		if _, exists := epm.flowCache[flowKey]; !exists {
			epm.flowCache[flowKey] = &FlowInfo{}
		}
		epm.flowCache[flowKey].MultiClassResult = multiScore
		epm.flowCache[flowKey].AttackType = multiScore.PredictedClass
		epm.flowCache[flowKey].AttackClass = multiScore.PredictedIndex
		epm.flowCache[flowKey].PerClassScores = multiScore.ThreatScores
		epm.flowCache[flowKey].ExpiresAt = now.Add(5 * time.Minute)
		epm.cacheMutex.Unlock()

		return multiScore, nil

	case err := <-errorChan:
		return nil, err

	case <-time.After(9 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func (epm *EnhancedPacketMonitor) flattenModelScores(
	modelScores map[string]map[string]float64) map[string]float64 {

	flattened := make(map[string]float64)
	for model, scores := range modelScores {
		maxScore := 0.0
		for _, score := range scores {
			if score > maxScore {
				maxScore = score
			}
		}
		flattened[model] = maxScore
	}
	return flattened
}

func (epm *EnhancedPacketMonitor) cacheCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		epm.cacheMutex.Lock()
		now := time.Now()
		for key, info := range epm.flowCache {
			if now.After(info.ExpiresAt) {
				delete(epm.flowCache, key)
			}
		}
		epm.cacheMutex.Unlock()
	}
}

func getAttackTypeColor(attackType string) string {
	switch attackType {
	case "U2R":
		return "🟣"
	case "DoS":
		return "🔴"
	case "R2L":
		return "🟡"
	case "Probe":
		return "🟠"
	default:
		return "⚪"
	}
}

func getProbabilityBar(prob float64) string {
	bars := int(prob * 20)
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

func mapBoolToAction(allowed bool) string {
	if allowed {
		return "ALLOW"
	}
	return "BLOCK"
}

// Network interface functions
func GetNetworkInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func DisplayInterfaceList(devices []pcap.Interface) {
	fmt.Println("📡 Available Network Interfaces:")
	fmt.Println(strings.Repeat("=", 80))

	for i, device := range devices {
		fmt.Printf("%d: %s\n", i, GetInterfaceDisplayName(device))

		for _, addr := range device.Addresses {
			if addr.IP.To4() != nil {
				fmt.Printf("   📍 IPv4: %s\n", addr.IP)
			} else if addr.IP.To16() != nil {
				fmt.Printf("   📍 IPv6: %s\n", addr.IP)
			}
		}

		var flags []string
		if len(device.Addresses) == 0 {
			flags = append(flags, "❌ No IP")
		}
		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() {
				flags = append(flags, "🔁 Loopback")
			}
		}

		if len(flags) > 0 {
			fmt.Printf("   🏷️  %s\n", strings.Join(flags, ", "))
		}
		fmt.Println()
	}
}

func GetInterfaceDisplayName(device pcap.Interface) string {
	name := device.Name
	if device.Description != "" {
		name = device.Description
	}

	name = strings.TrimPrefix(name, `\Device\NPF_`)

	if strings.Contains(strings.ToLower(name), "wireless") ||
		strings.Contains(strings.ToLower(name), "wifi") ||
		strings.Contains(strings.ToLower(name), "wi-fi") {
		return "📶 " + name
	}
	if strings.Contains(strings.ToLower(name), "ethernet") ||
		strings.Contains(strings.ToLower(name), "lan") {
		return "🔗 " + name
	}
	if strings.Contains(strings.ToLower(name), "loopback") ||
		strings.Contains(strings.ToLower(name), "localhost") {
		return "🔁 " + name
	}
	if strings.Contains(strings.ToLower(name), "bluetooth") {
		return "📱 " + name
	}

	return "🌐 " + name
}

func GetInterfaceDisplayNameByDevice(devices []pcap.Interface, deviceName string) string {
	for _, device := range devices {
		if device.Name == deviceName {
			return GetInterfaceDisplayName(device)
		}
	}
	return deviceName
}

func SelectInterface(devices []pcap.Interface) string {
	if len(devices) == 0 {
		fmt.Println("❌ No network interfaces found!")
		return ""
	}

	fmt.Println("\n📡 Available Network Interfaces:")
	fmt.Println(strings.Repeat("─", 50))

	for i, device := range devices {
		displayName := GetInterfaceDisplayName(device)

		ipList := []string{}
		for _, addr := range device.Addresses {
			if addr.IP.To4() != nil {
				ipList = append(ipList, addr.IP.String())
			}
		}

		ipStr := "no IP"
		if len(ipList) > 0 {
			ipStr = strings.Join(ipList, ", ")
		}

		fmt.Printf("[%d] %s\n", i, displayName)
		fmt.Printf("    📍 IP: %s\n", ipStr)

		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() {
				fmt.Printf("    🔁 Loopback interface\n")
				break
			}
		}
		fmt.Println()
	}

	fmt.Print("Select interface number [0]: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	choice := 0
	if input != "" {
		c, err := strconv.Atoi(input)
		if err == nil && c >= 0 && c < len(devices) {
			choice = c
		} else {
			fmt.Printf("⚠️  Invalid choice, using default (0)\n")
		}
	}

	selected := devices[choice]
	fmt.Printf("\n✅ Selected: %s\n", GetInterfaceDisplayName(selected))

	for _, addr := range selected.Addresses {
		if addr.IP.To4() != nil {
			fmt.Printf("   📍 Monitoring on IP: %s\n", addr.IP)
			break
		}
	}

	return selected.Name
}
