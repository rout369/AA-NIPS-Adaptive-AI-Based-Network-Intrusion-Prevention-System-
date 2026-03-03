package main

import (
    "embed"
    "encoding/json"
    "fmt"
    "html/template"
	"os"
    "net/http"
    "strconv"
    "strings"
    "sync"
    "time"
	"runtime"
	"os/exec"
)

//go:embed static templates
var content embed.FS

type DashboardServer struct {
    firewall *Firewall
    server   *http.Server
    mu       sync.RWMutex
    port     int
}

func NewDashboardServer(fw *Firewall, port int) *DashboardServer {
    return &DashboardServer{
        firewall: fw,
        port:     port,
    }
}

func (ds *DashboardServer) Start() error {
    mux := http.NewServeMux()
    
    // API endpoints
    mux.HandleFunc("/api/connections", ds.handleConnections)
    mux.HandleFunc("/api/connection/", ds.handleConnection)
    mux.HandleFunc("/api/feedback", ds.handleFeedback)
    mux.HandleFunc("/api/stats", ds.handleStats)
    mux.HandleFunc("/api/export", ds.handleExport)
    
    // Web interface
    mux.HandleFunc("/", ds.handleIndex)
    mux.Handle("/static/", http.FileServer(http.FS(content)))
    
    ds.server = &http.Server{
        Addr:    fmt.Sprintf(":%d", ds.port),
        Handler: mux,
    }
    
    fmt.Printf("\n🚀 Dashboard starting at http://localhost:%d\n", ds.port)
    fmt.Println("🌐 Opening in your default browser...")
    
    // Open browser automatically
    go func() {
        time.Sleep(500 * time.Millisecond)
        openBrowser(fmt.Sprintf("http://localhost:%d", ds.port))
    }()
    
    return ds.server.ListenAndServe()
}

func (ds *DashboardServer) Stop() error {
    if ds.server != nil {
        return ds.server.Close()
    }
    return nil
}

// API Handlers
func (ds *DashboardServer) handleConnections(w http.ResponseWriter, r *http.Request) {
    ds.firewall.historyLock.RLock()
    defer ds.firewall.historyLock.RUnlock()
    
    // Parse filters
    threatFilter := r.URL.Query().Get("threat")
    ipFilter := r.URL.Query().Get("ip")
    limit := 1000
    if l := r.URL.Query().Get("limit"); l != "" {
        if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
            limit = parsed
        }
    }
    
    // Filter connections
    var filtered []*ConnectionRecord
    for i := len(ds.firewall.history) - 1; i >= 0 && len(filtered) < limit; i-- {
        conn := ds.firewall.history[i]
        
        // Apply filters
        if threatFilter != "" && conn.ThreatLevel != threatFilter {
            continue
        }
        if ipFilter != "" && conn.SourceIP != ipFilter && conn.DestIP != ipFilter {
            continue
        }
        
        filtered = append(filtered, conn)
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(filtered)
}

func (ds *DashboardServer) handleConnection(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/api/connection/")
    id, err := strconv.Atoi(path)
    if err != nil {
        http.Error(w, "Invalid connection ID", http.StatusBadRequest)
        return
    }
    
    ds.firewall.historyLock.RLock()
    defer ds.firewall.historyLock.RUnlock()
    
    for _, conn := range ds.firewall.history {
        if conn.ID == id {
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(conn)
            return
        }
    }
    
    http.Error(w, "Connection not found", http.StatusNotFound)
}

func (ds *DashboardServer) handleFeedback(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var feedback struct {
        ConnectionID int    `json:"connection_id"`
        Reason       string `json:"reason"`
        Comment      string `json:"comment"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&feedback); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    ds.firewall.historyLock.Lock()
    defer ds.firewall.historyLock.Unlock()
    
    for _, conn := range ds.firewall.history {
        if conn.ID == feedback.ConnectionID {
            conn.Feedback = &FeedbackRecord{
                Reason:    feedback.Reason,
                Comment:   feedback.Comment,
                Timestamp: time.Now(),
            }
            
            // Send to ML service
            if ds.firewall.mlEnabled && ds.firewall.mlClient != nil {
                go ds.firewall.mlClient.SendFeedbackWithFeatures(
                    conn.SourceIP,
                    feedback.Reason,
                    conn.RuleID,
					conn.Features,      // Send the actual features
                    conn.FeatureNames,
                )
            }
            
            json.NewEncoder(w).Encode(map[string]string{
                "status":  "success",
                "message": "Feedback recorded",
            })
            return
        }
    }
    
    http.Error(w, "Connection not found", http.StatusNotFound)
}

func (ds *DashboardServer) handleStats(w http.ResponseWriter, r *http.Request) {
    ds.firewall.historyLock.RLock()
    defer ds.firewall.historyLock.RUnlock()
    
    stats := map[string]interface{}{
        "total_connections": len(ds.firewall.history),
        "total_allowed":     0,
        "total_blocked":     0,
        "feedback_count":    0,
        "false_positives":   0,
        "missed_attacks":    0,
        "correct_detections": 0,
        "threat_levels": map[string]int{
            "CRITICAL":    0,
            "SUSPICIOUS":  0,
            "MONITOR":     0,
            "NORMAL":      0,
        },
    }
    
    for _, conn := range ds.firewall.history {
        // Count actions
        if conn.FirewallAction == "ALLOW" {
            stats["total_allowed"] = stats["total_allowed"].(int) + 1
        } else {
            stats["total_blocked"] = stats["total_blocked"].(int) + 1
        }
        
        // Count threat levels
        stats["threat_levels"].(map[string]int)[conn.ThreatLevel]++
        
        // Count feedback
        if conn.Feedback != nil {
            stats["feedback_count"] = stats["feedback_count"].(int) + 1
            switch conn.Feedback.Reason {
            case "false_positive":
                stats["false_positives"] = stats["false_positives"].(int) + 1
            case "missed_attack":
                stats["missed_attacks"] = stats["missed_attacks"].(int) + 1
            case "correct":
                stats["correct_detections"] = stats["correct_detections"].(int) + 1
            }
        }
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(stats)
}

func (ds *DashboardServer) handleExport(w http.ResponseWriter, r *http.Request) {
    ds.firewall.historyLock.RLock()
    defer ds.firewall.historyLock.RUnlock()
    
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Content-Disposition", "attachment; filename=firewall-history.json")
    json.NewEncoder(w).Encode(ds.firewall.history)
}

func (ds *DashboardServer) handleIndex(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFS(content, "templates/dashboard.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

// Helper to open browser
func openBrowser(url string) {
    var err error
    switch {
    case isWindows():
        err = execCommand("rundll32", "url.dll,FileProtocolHandler", url)
    case isMac():
        err = execCommand("open", url)
    case isLinux():
        err = execCommand("xdg-open", url)
    }
    if err != nil {
        fmt.Printf("⚠️  Could not open browser automatically: %v\n", err)
    }
}

func isWindows() bool {
    return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func isMac() bool {
    return !isWindows() && os.Getenv("HOME") != "" && strings.Contains(runtime.GOOS, "darwin")
}

func isLinux() bool {
    return !isWindows() && !isMac() && strings.Contains(runtime.GOOS, "linux")
}

func execCommand(name string, args ...string) error {
    cmd := exec.Command(name, args...)
    return cmd.Start()
}