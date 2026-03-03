package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"time"
)

// MLClient handles communication with the Python ML service
type MLClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Enabled    bool
}

// MaliciousIP represents a detected malicious IP with confidence and attack type
type MaliciousIP struct {
	IP          string  `json:"ip"`
	Confidence  float64 `json:"confidence"`
	AttackType  string  `json:"attack_type"`  // DoS, Probe, R2L, U2R
	AttackClass int     `json:"attack_class"` // 1-4 (0 is Normal)
}

// PCAPAnalysisResult represents the response from /analyze_pcap
type PCAPAnalysisResult struct {
	TotalPackets        int           `json:"total_packets"`
	MaliciousPackets    int           `json:"malicious_packets"`
	MaliciousPercentage float64       `json:"malicious_percentage"`
	RiskLevel           string        `json:"risk_level"`
	Recommendation      string        `json:"recommendation"`
	MaliciousIPs        []MaliciousIP `json:"malicious_ips"`
	ThresholdUsed       float64       `json:"threshold_used"`
}

// EnsembleScore represents the response from /ensemble_score (binary)
type EnsembleScore struct {
	ThreatScore        float64            `json:"threat_score"`
	ConsensusPercentage float64           `json:"consensus_percentage"`
	ConsensusLevel     string             `json:"consensus_level"`
	ModelScores        map[string]float64 `json:"model_scores"`
	BestModel          struct {
		Name  string  `json:"name"`
		Score float64 `json:"score"`
	} `json:"best_model"`
	IsMalicious        bool               `json:"is_malicious"`
}

// MultiClassScore represents the response from /multiclass_score (5-class)
type MultiClassScore struct {
	ThreatScores        map[string]float64              `json:"threat_scores"`          // Per-class probabilities
	PredictedClass      string                           `json:"predicted_class"`        // "Normal", "DoS", "Probe", "R2L", "U2R"
	PredictedIndex      int                              `json:"predicted_index"`        // 0-4
	Confidence          float64                          `json:"confidence"`             // Max probability
	ConsensusPercentage float64                          `json:"consensus_percentage"`
	ConsensusLevel      string                           `json:"consensus_level"`
	ModelScores         map[string]map[string]float64    `json:"model_scores"`           // Each model's per-class scores
	BestModel           struct {
		Name  string `json:"name"`
		Class string `json:"class"`
		Score float64 `json:"score"`
	} `json:"best_model"`
	IsMalicious bool `json:"is_malicious"` // True if not Normal
}

// ModelInfo represents the response from /model_info
type ModelInfo struct {
	Models            []string          `json:"models"`
	BestModel         string            `json:"best_model"`
	BestModelF1       float64           `json:"best_model_f1"`
	FeaturesCount     int               `json:"features_count"`
	Features          []string          `json:"features"`
	Weights           map[string]float64 `json:"weights"`
	Classes           []string          `json:"classes"`
}

// FeedbackWithFeatures represents feedback with actual feature data
type FeedbackWithFeatures struct {
	IP           string                 `json:"ip"`
	Reason       string                 `json:"reason"`
	RuleID       string                 `json:"rule_id,omitempty"`
	Features     map[string]interface{} `json:"features"`
	FeatureNames []string               `json:"feature_names"`
	Timestamp    time.Time              `json:"timestamp"`
}

// RetrainResult represents the response from retraining
type RetrainResult struct {
	Success         bool               `json:"success"`
	OldAccuracy     float64            `json:"old_accuracy"`
	NewAccuracy     float64            `json:"new_accuracy"`
	BestModel       string             `json:"best_model"`
	ModelAccuracies map[string]float64 `json:"model_accuracies"`
	SamplesUsed     int                `json:"samples_used"`
	Message         string             `json:"message"`
}

// AnomalyScore represents the response from /anomaly_score
type AnomalyScore struct {
	AnomalyScore    float64 `json:"anomaly_score"`
	AnomalyLevel    string  `json:"anomaly_level"`
	IsAnomaly       bool    `json:"is_anomaly"`
	Threshold       float64 `json:"threshold"`
	StrictThreshold float64 `json:"strict_threshold"`
}

// Feedback represents simple feedback
type Feedback struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
	RuleID string `json:"rule_id,omitempty"`
}

// NewMLClient creates a new ML client
func NewMLClient(baseURL string) *MLClient {
	return &MLClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second, // Increased timeout for 5-class model
		},
		Enabled: true,
	}
}

// Health checks if ML service is reachable
func (c *MLClient) Health() (map[string]interface{}, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/health")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// IsServiceAvailable checks if ML service is running
func (c *MLClient) IsServiceAvailable() bool {
	_, err := c.Health()
	return err == nil
}

// MultiClassScore sends features and returns 5-class threat scores
func (c *MLClient) MultiClassScore(features map[string]interface{}) (*MultiClassScore, error) {
	jsonData, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/multiclass_score", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result MultiClassScore
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &result, nil
}

// EnsembleScore (kept for backward compatibility)
func (c *MLClient) EnsembleScore(features map[string]interface{}) (*EnsembleScore, error) {
	jsonData, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/ensemble_score", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result EnsembleScore
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &result, nil
}

// AnalyzePCAP sends a PCAP file to ML service and returns analysis
func (c *MLClient) AnalyzePCAP(pcapPath string, threshold float64) (*PCAPAnalysisResult, error) {
	file, err := os.Open(pcapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "traffic.pcap")
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %v", err)
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %v", err)
	}

	err = writer.WriteField("threshold", fmt.Sprintf("%f", threshold))
	if err != nil {
		return nil, fmt.Errorf("failed to write threshold: %v", err)
	}
	writer.Close()

	req, err := http.NewRequest("POST", c.BaseURL+"/analyze_pcap", body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ML service returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result PCAPAnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &result, nil
}

// GetModelInfo retrieves information about loaded models
func (c *MLClient) GetModelInfo() (*ModelInfo, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/model_info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	// Print the raw JSON response
	// fmt.Printf("🔍 DEBUG - Raw JSON response: %s\n", string(bodyBytes))

	var result ModelInfo
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, err
	}
	
	// Print the parsed struct
	// fmt.Printf("🔍 DEBUG - Parsed ModelInfo: BestModel=%s, BestModelF1=%f\n", 
	// 	result.BestModel, result.BestModelF1)
	
	return &result, nil
}

// SendFeedback sends feedback about false positives to ML service
func (c *MLClient) SendFeedback(ip, reason, ruleID string) error {
	feedback := Feedback{
		IP:     ip,
		Reason: reason,
		RuleID: ruleID,
	}

	jsonData, err := json.Marshal(feedback)
	if err != nil {
		return fmt.Errorf("failed to marshal feedback: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/feedback", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send feedback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("feedback failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// SendFeedbackWithFeatures sends feedback with actual feature vectors
func (c *MLClient) SendFeedbackWithFeatures(ip, reason, ruleID string, features map[string]interface{}, featureNames []string) error {
	feedback := FeedbackWithFeatures{
		IP:           ip,
		Reason:       reason,
		RuleID:       ruleID,
		Features:     features,
		FeatureNames: featureNames,
		Timestamp:    time.Now(),
	}

	jsonData, err := json.Marshal(feedback)
	if err != nil {
		return fmt.Errorf("failed to marshal feedback: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/feedback/with_features", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send feedback: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("feedback failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// GetFeedbackStats retrieves feedback statistics
func (c *MLClient) GetFeedbackStats() (map[string]int, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/feedback/stats")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get stats: status %d", resp.StatusCode)
	}

	var result map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// RetrainModels triggers model retraining with feedback
func (c *MLClient) RetrainModels() (*RetrainResult, error) {
	resp, err := c.HTTPClient.Post(c.BaseURL+"/retrain", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("retrain failed: %s", string(bodyBytes))
	}

	var result RetrainResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// GetRetrainStatus checks if retraining is possible and returns progress
func (c *MLClient) GetRetrainStatus() (map[string]interface{}, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/retrain/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get retrain status: status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAnomalyScore sends features and returns anomaly score
func (c *MLClient) GetAnomalyScore(features map[string]interface{}) (*AnomalyScore, error) {
	jsonData, err := json.Marshal(features)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal features: %v", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/anomaly_score", "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anomaly detection failed: %s", string(bodyBytes))
	}

	var result AnomalyScore
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &result, nil
}

// ScoreFlow (kept for backward compatibility)
func (c *MLClient) ScoreFlow(features map[string]interface{}) (*EnsembleScore, error) {
	return c.EnsembleScore(features)
}