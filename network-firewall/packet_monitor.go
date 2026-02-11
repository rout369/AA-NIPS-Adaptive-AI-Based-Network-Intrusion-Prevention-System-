// package main

// import (
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"
// 	"os/signal"
// 	"strings"
// 	"sync"
// 	"syscall"
// 	"time"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	"github.com/google/gopacket/pcap"
// )

// // ConnectionStats stores statistics for each connection
// type ConnectionStats struct {
// 	PacketCount int
// 	ByteCount   int
// 	FirstSeen   time.Time
// 	LastSeen    time.Time
// 	Protocol    string
// }

// // EnhancedPacketMonitor with statistics
// type EnhancedPacketMonitor struct {
// 	handle      *pcap.Handle
// 	device      string
// 	uniqueIPs   map[string]bool
// 	connections map[string]*ConnectionStats
// 	mutex       sync.RWMutex
// 	startTime   time.Time
// }

// func NewEnhancedPacketMonitor(device string) *EnhancedPacketMonitor {
// 	return &EnhancedPacketMonitor{
// 		device:      device,
// 		uniqueIPs:   make(map[string]bool),
// 		connections: make(map[string]*ConnectionStats),
// 		startTime:   time.Now(),
// 	}
// }

// func (epm *EnhancedPacketMonitor) Start() error {
// 	var err error

// 	epm.handle, err = pcap.OpenLive(epm.device, 1600, true, pcap.BlockForever)
// 	if err != nil {
// 		return err
// 	}
// 	defer epm.handle.Close()

// 	// Capture TCP, UDP, and ICMP
// 	err = epm.handle.SetBPFFilter("tcp or udp or icmp or icmp6")
// 	if err != nil {
// 		return err
// 	}

// 	fmt.Printf("🎯 Enhanced packet monitor started on %s\n", epm.getInterfaceName(epm.device))
// 	fmt.Println("📊 Live packet display active...")
// 	fmt.Println("🛑 Press Ctrl+C to stop and show statistics\n")
// 	fmt.Println(strings.Repeat("─", 80))

// 	// Start statistics printer
// 	go epm.printStatistics()

// 	packetSource := gopacket.NewPacketSource(epm.handle, epm.handle.LinkType())
// 	for packet := range packetSource.Packets() {
// 		epm.processEnhancedPacket(packet)
// 	}

// 	return nil
// }

// func (epm *EnhancedPacketMonitor) processEnhancedPacket(packet gopacket.Packet) {
// 	epm.mutex.Lock()
// 	defer epm.mutex.Unlock()

// 	networkLayer := packet.NetworkLayer()
// 	if networkLayer == nil {
// 		return
// 	}

// 	var srcIP, dstIP net.IP
// 	var protocol string

// 	// Handle different IP versions
// 	switch ipLayer := networkLayer.(type) {
// 	case *layers.IPv4:
// 		srcIP = ipLayer.SrcIP
// 		dstIP = ipLayer.DstIP
// 		protocol = "IPv4"
// 	case *layers.IPv6:
// 		srcIP = ipLayer.SrcIP
// 		dstIP = ipLayer.DstIP
// 		protocol = "IPv6"
// 	default:
// 		return
// 	}

// 	srcIPStr := srcIP.String()
// 	dstIPStr := dstIP.String()

// 	// Track unique IPs
// 	if !epm.uniqueIPs[srcIPStr] {
// 		epm.uniqueIPs[srcIPStr] = true
// 		fmt.Printf("🆕 NEW IP DETECTED: %s\n", srcIPStr)
// 	}
// 	if !epm.uniqueIPs[dstIPStr] {
// 		epm.uniqueIPs[dstIPStr] = true
// 		fmt.Printf("🆕 NEW IP DETECTED: %s\n", dstIPStr)
// 	}

// 	// Process transport layer
// 	transportLayer := packet.TransportLayer()
// 	appLayer := packet.ApplicationLayer()

// 	// Create connection key
// 	connKey := fmt.Sprintf("%s->%s", srcIPStr, dstIPStr)

// 	// Update or create connection stats
// 	if stats, exists := epm.connections[connKey]; exists {
// 		stats.PacketCount++
// 		stats.ByteCount += len(packet.Data())
// 		stats.LastSeen = time.Now()
// 	} else {
// 		epm.connections[connKey] = &ConnectionStats{
// 			PacketCount: 1,
// 			ByteCount:   len(packet.Data()),
// 			FirstSeen:   time.Now(),
// 			LastSeen:    time.Now(),
// 			Protocol:    protocol,
// 		}
// 		fmt.Printf("🔗 NEW CONNECTION: %s → %s\n", srcIPStr, dstIPStr)
// 	}

// 	// Display live packet info
// 	epm.displayLivePacketInfo(packet, srcIPStr, dstIPStr, protocol, transportLayer, appLayer)
// }

// func (epm *EnhancedPacketMonitor) displayLivePacketInfo(packet gopacket.Packet, srcIP, dstIP, protocol string, transportLayer gopacket.TransportLayer, appLayer gopacket.ApplicationLayer) {
// 	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
	
// 	var info strings.Builder

// 	// Basic info
// 	info.WriteString(fmt.Sprintf("🕒 [%s] ", timestamp))
// 	info.WriteString(fmt.Sprintf("🌐 %s %s → %s", protocol, srcIP, dstIP))

// 	// Transport layer info
// 	if transportLayer != nil {
// 		switch layer := transportLayer.(type) {
// 		case *layers.TCP:
// 			info.WriteString(fmt.Sprintf(" | 🚦 TCP %d→%d", layer.SrcPort, layer.DstPort))
// 			info.WriteString(fmt.Sprintf(" | 📊 Seq:%d Ack:%d", layer.Seq, layer.Ack))
// 			info.WriteString(fmt.Sprintf(" | 🚩 %s", epm.getTCPFlags(layer)))
// 			info.WriteString(fmt.Sprintf(" | 🪟 Win:%d", layer.Window))
// 		case *layers.UDP:
// 			info.WriteString(fmt.Sprintf(" | 🚦 UDP %d→%d", layer.SrcPort, layer.DstPort))
// 			info.WriteString(fmt.Sprintf(" | 📏 Len:%d", layer.Length))
// 		}
// 	}

// 	// Application layer info
// 	if appLayer != nil {
// 		payload := appLayer.Payload()
// 		if len(payload) > 0 {
// 			info.WriteString(fmt.Sprintf(" | 📦 AppData:%d bytes", len(payload)))
// 		}
// 	}

// 	// Packet size
// 	info.WriteString(fmt.Sprintf(" | 💾 Size:%d bytes", len(packet.Data())))

// 	fmt.Println(info.String())
// }

// func (epm *EnhancedPacketMonitor) getTCPFlags(tcp *layers.TCP) string {
// 	flags := ""
// 	if tcp.SYN { flags += "S" }
// 	if tcp.ACK { flags += "A" }
// 	if tcp.FIN { flags += "F" }
// 	if tcp.RST { flags += "R" }
// 	if tcp.PSH { flags += "P" }
// 	if tcp.URG { flags += "U" }
// 	if flags == "" { flags = "-" }
// 	return flags
// }

// func (epm *EnhancedPacketMonitor) printStatistics() {
// 	ticker := time.NewTicker(60 * time.Second)
// 	defer ticker.Stop()
	
// 	for range ticker.C {
// 		epm.mutex.RLock()
// 		fmt.Printf("\n%s STATISTICS UPDATE %s\n", strings.Repeat("▀", 30), strings.Repeat("▀", 30))
// 		fmt.Printf("🕒 Uptime: %s\n", time.Since(epm.startTime).Round(time.Second))
// 		fmt.Printf("🌐 Unique IPs: %d\n", len(epm.uniqueIPs))
// 		fmt.Printf("🔗 Active connections: %d\n", len(epm.connections))
// 		fmt.Printf("📦 Top connections:\n")
		
// 		// Show top 5 connections by packet count
// 		topConnections := 0
// 		for conn, stats := range epm.connections {
// 			if topConnections >= 5 {
// 				break
// 			}
// 			fmt.Printf("   %s: %d packets, %d bytes\n", conn, stats.PacketCount, stats.ByteCount)
// 			topConnections++
// 		}
// 		fmt.Printf("%s\n\n", strings.Repeat("▄", 80))
// 		epm.mutex.RUnlock()
// 	}
// }

// func (epm *EnhancedPacketMonitor) getInterfaceName(device string) string {
// 	// Clean up Windows device names and try to identify interface types
// 	cleanName := strings.TrimPrefix(device, `\Device\NPF_`)
	
// 	// Try to get interface details
// 	devices, err := pcap.FindAllDevs()
// 	if err != nil {
// 		return device
// 	}
	
// 	for _, dev := range devices {
// 		if dev.Name == device {
// 			if len(dev.Description) > 0 {
// 				return dev.Description
// 			}
// 			// Try to determine interface type from addresses
// 			for _, addr := range dev.Addresses {
// 				if addr.IP.IsLoopback() {
// 					return "Loopback Adapter"
// 				}
// 				if strings.Contains(dev.Description, "Wireless") || strings.Contains(dev.Name, "Wi-Fi") {
// 					return "Wi-Fi Adapter"
// 				}
// 				if strings.Contains(dev.Description, "Ethernet") {
// 					return "Ethernet Adapter"
// 				}
// 			}
// 		}
// 	}
	
// 	return cleanName
// }

// func getNetworkInterfaces() ([]pcap.Interface, error) {
// 	devices, err := pcap.FindAllDevs()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return devices, nil
// }

// func displayInterfaceList(devices []pcap.Interface) {
// 	fmt.Println("📡 Available Network Interfaces:")
// 	fmt.Println(strings.Repeat("=", 80))
	
// 	for i, device := range devices {
// 		fmt.Printf("%d: %s\n", i, getInterfaceDisplayName(device))
		
// 		// Show IP addresses
// 		for _, addr := range device.Addresses {
// 			if addr.IP.To4() != nil {
// 				fmt.Printf("   📍 IPv4: %s\n", addr.IP)
// 			} else if addr.IP.To16() != nil {
// 				fmt.Printf("   📍 IPv6: %s\n", addr.IP)
// 			}
// 		}
		
// 		// Show interface flags
// 		var flags []string
// 		if len(device.Addresses) == 0 {
// 			flags = append(flags, "❌ No IP")
// 		}
// 		for _, addr := range device.Addresses {
// 			if addr.IP.IsLoopback() {
// 				flags = append(flags, "🔁 Loopback")
// 			}
// 		}
		
// 		if len(flags) > 0 {
// 			fmt.Printf("   🏷️  %s\n", strings.Join(flags, ", "))
// 		}
// 		fmt.Println()
// 	}
// }

// func getInterfaceDisplayName(device pcap.Interface) string {
// 	name := device.Name
// 	if device.Description != "" {
// 		name = device.Description
// 	}
	
// 	// Clean up Windows names
// 	name = strings.TrimPrefix(name, `\Device\NPF_`)
	
// 	// Add emojis based on interface type
// 	if strings.Contains(strings.ToLower(name), "wireless") || 
// 	   strings.Contains(strings.ToLower(name), "wifi") ||
// 	   strings.Contains(strings.ToLower(name), "wi-fi") {
// 		return "📶 " + name
// 	}
// 	if strings.Contains(strings.ToLower(name), "ethernet") || 
// 	   strings.Contains(strings.ToLower(name), "lan") {
// 		return "🔗 " + name
// 	}
// 	if strings.Contains(strings.ToLower(name), "loopback") ||
// 	   strings.Contains(strings.ToLower(name), "localhost") {
// 		return "🔁 " + name
// 	}
// 	if strings.Contains(strings.ToLower(name), "bluetooth") {
// 		return "📱 " + name
// 	}
	
// 	return "🌐 " + name
// }

// func selectInterface(devices []pcap.Interface) string {
// 	if len(devices) == 0 {
// 		log.Fatal("❌ No network interfaces found!")
// 	}

// 	// Try to find a non-loopback interface with IP addresses
// 	for _, device := range devices {
// 		hasNonLoopbackIP := false
// 		for _, addr := range device.Addresses {
// 			if !addr.IP.IsLoopback() && addr.IP.To4() != nil {
// 				hasNonLoopbackIP = true
// 				break
// 			}
// 		}
// 		if hasNonLoopbackIP {
// 			fmt.Printf("✅ Auto-selected interface: %s\n", getInterfaceDisplayName(device))
// 			return device.Name
// 		}
// 	}

// 	// Fallback to first interface
// 	fmt.Printf("⚠️  Using first interface: %s\n", getInterfaceDisplayName(devices[0]))
// 	return devices[0].Name
// }

// func main() {
// 	fmt.Println("🚀 Go Packet Monitor - Real Time Network Traffic Analyzer")
// 	fmt.Println(strings.Repeat("=", 80))

// 	// Get available devices
// 	devices, err := getNetworkInterfaces()
// 	if err != nil {
// 		log.Fatal("❌ Error finding network interfaces:", err)
// 	}

// 	// Display interface list
// 	displayInterfaceList(devices)

// 	// Auto-select best interface
// 	selectedInterface := selectInterface(devices)

// 	// Handle interrupt signal for graceful shutdown
// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

// 	monitor := NewEnhancedPacketMonitor(selectedInterface)

// 	// Start monitoring in goroutine
// 	go func() {
// 		if err := monitor.Start(); err != nil {
// 			log.Fatal("❌ Error starting packet monitor:", err)
// 		}
// 	}()

// 	// Wait for interrupt
// 	<-sigChan
// 	fmt.Println("\n\n🛑 Shutting down packet monitor...")
	
// 	monitor.mutex.RLock()
// 	fmt.Printf("\n%s FINAL STATISTICS %s\n", strings.Repeat("⭐", 20), strings.Repeat("⭐", 20))
// 	fmt.Printf("📊 Monitoring duration: %s\n", time.Since(monitor.startTime).Round(time.Second))
// 	fmt.Printf("🌐 Total unique IP addresses: %d\n", len(monitor.uniqueIPs))
// 	fmt.Printf("🔗 Total connections tracked: %d\n", len(monitor.connections))
// 	fmt.Printf("📦 Top 10 connections:\n")
	
// 	// Display top 10 connections
// 	count := 0
// 	for conn, stats := range monitor.connections {
// 		if count >= 10 {
// 			break
// 		}
// 		fmt.Printf("   %s: %d packets, %d bytes\n", conn, stats.PacketCount, stats.ByteCount)
// 		count++
// 	}
// 	fmt.Println(strings.Repeat("⭐", 60))
// 	monitor.mutex.RUnlock()
// }




package main

import (
	"fmt"
	"log"
	"net"
	// "os"
	// "os/signal"
	"strings"
	"sync"
	// "syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ConnectionStats stores statistics for each connection
type ConnectionStats struct {
	PacketCount int
	ByteCount   int
	FirstSeen   time.Time
	LastSeen    time.Time
	Protocol    string
}

// EnhancedPacketMonitor with statistics AND firewall integration
type EnhancedPacketMonitor struct {
	handle      *pcap.Handle
	device      string
	uniqueIPs   map[string]bool
	connections map[string]*ConnectionStats
	mutex       sync.RWMutex
	startTime   time.Time
	firewall    *Firewall  // 🆕 Add firewall reference
}

// 🆕 Update constructor to accept firewall
func NewEnhancedPacketMonitor(device string, firewall *Firewall) *EnhancedPacketMonitor {
	return &EnhancedPacketMonitor{
		device:      device,
		uniqueIPs:   make(map[string]bool),
		connections: make(map[string]*ConnectionStats),
		startTime:   time.Now(),
		firewall:    firewall,  // 🆕 Store firewall reference
	}
}

func (epm *EnhancedPacketMonitor) Start() error {
	var err error

	epm.handle, err = pcap.OpenLive(epm.device, 1600, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer epm.handle.Close()

	// Capture TCP, UDP, and ICMP
	err = epm.handle.SetBPFFilter("tcp or udp or icmp or icmp6")
	if err != nil {
		return err
	}

	fmt.Printf("🎯 Enhanced packet monitor started on %s\n", epm.getInterfaceName(epm.device))
	fmt.Println("📊 Live packet display active...")
	fmt.Println("🛑 Press Ctrl+C to stop and show statistics\n")
	fmt.Println(strings.Repeat("─", 80))

	// Start statistics printer
	go epm.printStatistics()

	packetSource := gopacket.NewPacketSource(epm.handle, epm.handle.LinkType())
	for packet := range packetSource.Packets() {
		epm.processEnhancedPacket(packet)
	}

	return nil
}

// 🆕 UPDATED: processEnhancedPacket now uses firewall for real-time decisions
func (epm *EnhancedPacketMonitor) processEnhancedPacket(packet gopacket.Packet) {
	epm.mutex.Lock()
	defer epm.mutex.Unlock()

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP net.IP
	var protocol string

	// Handle different IP versions
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

	// Track unique IPs
	if !epm.uniqueIPs[srcIPStr] {
		epm.uniqueIPs[srcIPStr] = true
		fmt.Printf("🆕 NEW IP DETECTED: %s\n", srcIPStr)
	}
	if !epm.uniqueIPs[dstIPStr] {
		epm.uniqueIPs[dstIPStr] = true
		fmt.Printf("🆕 NEW IP DETECTED: %s\n", dstIPStr)
	}

	// Process transport layer
	transportLayer := packet.TransportLayer()
	
	// Extract port information for firewall checking
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
	} else if networkLayer != nil {
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

	// 🆕 REAL-TIME FIREWALL INTEGRATION
	if epm.firewall != nil && transportProtocol != "" {
		// Use the firewall to check if this connection should be blocked
		// Note: We're using detection mode only - no actual blocking
		allowed := epm.firewall.CheckConnection(srcIPStr, dstIPStr, dstPort, transportProtocol)
		
		// 🆕 Display firewall decision in real-time
		if allowed {
			fmt.Printf("🟢 FIREWALL ALLOW: %s:%d → %s:%d %s\n", 
				srcIPStr, srcPort, dstIPStr, dstPort, transportProtocol)
		} else {
			fmt.Printf("🔴 FIREWALL BLOCK: %s:%d → %s:%d %s (Would be blocked)\n", 
				srcIPStr, srcPort, dstIPStr, dstPort, transportProtocol)
		}
	}

	// Create connection key
	connKey := fmt.Sprintf("%s->%s", srcIPStr, dstIPStr)

	// Update or create connection stats
	if stats, exists := epm.connections[connKey]; exists {
		stats.PacketCount++
		stats.ByteCount += len(packet.Data())
		stats.LastSeen = time.Now()
	} else {
		epm.connections[connKey] = &ConnectionStats{
			PacketCount: 1,
			ByteCount:   len(packet.Data()),
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Protocol:    protocol,
		}
		fmt.Printf("🔗 NEW CONNECTION: %s → %s\n", srcIPStr, dstIPStr)
	}

	// Display live packet info
	appLayer := packet.ApplicationLayer()
	epm.displayLivePacketInfo(packet, srcIPStr, dstIPStr, protocol, transportLayer, appLayer)
}

func (epm *EnhancedPacketMonitor) displayLivePacketInfo(packet gopacket.Packet, srcIP, dstIP, protocol string, transportLayer gopacket.TransportLayer, appLayer gopacket.ApplicationLayer) {
	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
	
	var info strings.Builder

	// Basic info
	info.WriteString(fmt.Sprintf("🕒 [%s] ", timestamp))
	info.WriteString(fmt.Sprintf("🌐 %s %s → %s", protocol, srcIP, dstIP))

	// Transport layer info
	if transportLayer != nil {
		switch layer := transportLayer.(type) {
		case *layers.TCP:
			info.WriteString(fmt.Sprintf(" | 🚦 TCP %d→%d", layer.SrcPort, layer.DstPort))
			info.WriteString(fmt.Sprintf(" | 📊 Seq:%d Ack:%d", layer.Seq, layer.Ack))
			info.WriteString(fmt.Sprintf(" | 🚩 %s", epm.getTCPFlags(layer)))
			info.WriteString(fmt.Sprintf(" | 🪟 Win:%d", layer.Window))
		case *layers.UDP:
			info.WriteString(fmt.Sprintf(" | 🚦 UDP %d→%d", layer.SrcPort, layer.DstPort))
			info.WriteString(fmt.Sprintf(" | 📏 Len:%d", layer.Length))
		}
	}

	// Application layer info
	if appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			info.WriteString(fmt.Sprintf(" | 📦 AppData:%d bytes", len(payload)))
		}
	}

	// Packet size
	info.WriteString(fmt.Sprintf(" | 💾 Size:%d bytes", len(packet.Data())))

	fmt.Println(info.String())
}

func (epm *EnhancedPacketMonitor) getTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN { flags += "S" }
	if tcp.ACK { flags += "A" }
	if tcp.FIN { flags += "F" }
	if tcp.RST { flags += "R" }
	if tcp.PSH { flags += "P" }
	if tcp.URG { flags += "U" }
	if flags == "" { flags = "-" }
	return flags
}

func (epm *EnhancedPacketMonitor) printStatistics() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		epm.mutex.RLock()
		fmt.Printf("\n%s STATISTICS UPDATE %s\n", strings.Repeat("▀", 30), strings.Repeat("▀", 30))
		fmt.Printf("🕒 Uptime: %s\n", time.Since(epm.startTime).Round(time.Second))
		fmt.Printf("🌐 Unique IPs: %d\n", len(epm.uniqueIPs))
		fmt.Printf("🔗 Active connections: %d\n", len(epm.connections))
		
		// 🆕 Show firewall stats too
		if epm.firewall != nil {
			fwStats := epm.firewall.GetStats()
			fmt.Printf("🛡️  Firewall Decisions: %d allowed, %d blocked\n", 
				fwStats["allowed_connections"], fwStats["blocked_connections"])
		}
		
		fmt.Printf("📦 Top connections:\n")
		
		// Show top 5 connections by packet count
		topConnections := 0
		for conn, stats := range epm.connections {
			if topConnections >= 5 {
				break
			}
			fmt.Printf("   %s: %d packets, %d bytes\n", conn, stats.PacketCount, stats.ByteCount)
			topConnections++
		}
		fmt.Printf("%s\n\n", strings.Repeat("▄", 80))
		epm.mutex.RUnlock()
	}
}

func (epm *EnhancedPacketMonitor) getInterfaceName(device string) string {
	// Clean up Windows device names and try to identify interface types
	cleanName := strings.TrimPrefix(device, `\Device\NPF_`)
	
	// Try to get interface details
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return device
	}
	
	for _, dev := range devices {
		if dev.Name == device {
			if len(dev.Description) > 0 {
				return dev.Description
			}
			// Try to determine interface type from addresses
			for _, addr := range dev.Addresses {
				if addr.IP.IsLoopback() {
					return "Loopback Adapter"
				}
				if strings.Contains(dev.Description, "Wireless") || strings.Contains(dev.Name, "Wi-Fi") {
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

func getNetworkInterfaces() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	return devices, nil
}

func displayInterfaceList(devices []pcap.Interface) {
	fmt.Println("📡 Available Network Interfaces:")
	fmt.Println(strings.Repeat("=", 80))
	
	for i, device := range devices {
		fmt.Printf("%d: %s\n", i, getInterfaceDisplayName(device))
		
		// Show IP addresses
		for _, addr := range device.Addresses {
			if addr.IP.To4() != nil {
				fmt.Printf("   📍 IPv4: %s\n", addr.IP)
			} else if addr.IP.To16() != nil {
				fmt.Printf("   📍 IPv6: %s\n", addr.IP)
			}
		}
		
		// Show interface flags
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

func getInterfaceDisplayName(device pcap.Interface) string {
	name := device.Name
	if device.Description != "" {
		name = device.Description
	}
	
	// Clean up Windows names
	name = strings.TrimPrefix(name, `\Device\NPF_`)
	
	// Add emojis based on interface type
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

func selectInterface(devices []pcap.Interface) string {
	if len(devices) == 0 {
		log.Fatal("❌ No network interfaces found!")
	}

	// Try to find a non-loopback interface with IP addresses
	for _, device := range devices {
		hasNonLoopbackIP := false
		for _, addr := range device.Addresses {
			if !addr.IP.IsLoopback() && addr.IP.To4() != nil {
				hasNonLoopbackIP = true
				break
			}
		}
		if hasNonLoopbackIP {
			fmt.Printf("✅ Auto-selected interface: %s\n", getInterfaceDisplayName(device))
			return device.Name
		}
	}

	// Fallback to first interface
	fmt.Printf("⚠️  Using first interface: %s\n", getInterfaceDisplayName(devices[0]))
	return devices[0].Name
}

// 🚫 REMOVE THIS MAIN FUNCTION - Keep only the one in main.go
// func main() {
// 	fmt.Println("🚀 Go Packet Monitor - Real Time Network Traffic Analyzer")
// 	fmt.Println(strings.Repeat("=", 80))
// 
// 	// Get available devices
// 	devices, err := getNetworkInterfaces()
// 	if err != nil {
// 		log.Fatal("❌ Error finding network interfaces:", err)
// 	}
// 
// 	// Display interface list
// 	displayInterfaceList(devices)
// 
// 	// Auto-select best interface
// 	selectedInterface := selectInterface(devices)
// 
// 	// Handle interrupt signal for graceful shutdown
// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
// 
// 	monitor := NewEnhancedPacketMonitor(selectedInterface)
// 
// 	// Start monitoring in goroutine
// 	go func() {
// 		if err := monitor.Start(); err != nil {
// 			log.Fatal("❌ Error starting packet monitor:", err)
// 		}
// 	}()
// 
// 	// Wait for interrupt
// 	<-sigChan
// 	fmt.Println("\n\n🛑 Shutting down packet monitor...")
// 	
// 	monitor.mutex.RLock()
// 	fmt.Printf("\n%s FINAL STATISTICS %s\n", strings.Repeat("⭐", 20), strings.Repeat("⭐", 20))
// 	fmt.Printf("📊 Monitoring duration: %s\n", time.Since(monitor.startTime).Round(time.Second))
// 	fmt.Printf("🌐 Total unique IP addresses: %d\n", len(monitor.uniqueIPs))
// 	fmt.Printf("🔗 Total connections tracked: %d\n", len(monitor.connections))
// 	fmt.Printf("📦 Top 10 connections:\n")
// 	
// 	// Display top 10 connections
// 	count := 0
// 	for conn, stats := range monitor.connections {
// 		if count >= 10 {
// 			break
// 		}
// 		fmt.Printf("   %s: %d packets, %d bytes\n", conn, stats.PacketCount, stats.ByteCount)
// 		count++
// 	}
// 	fmt.Println(strings.Repeat("⭐", 60))
// 	monitor.mutex.RUnlock()
// }