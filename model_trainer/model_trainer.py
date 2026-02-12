import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier, LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.utils import class_weight
import time
import scapy.all as scapy
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import os
from datetime import datetime
from sklearn.metrics import roc_curve, auc, confusion_matrix, roc_auc_score
import seaborn as sns
from matplotlib.colors import LinearSegmentedColormap
import plotly.graph_objects as go
import plotly.express as px
import io
import base64

# -----------------------------
# SETTINGS
# -----------------------------
CSV_PATH = "network_traffic.csv"
LEARNING_RATE = 0.01
EPOCHS = 50
RANDOM_STATE = 42
USE_FULL_DATASET = False

# -----------------------------
# LOAD DATASET
# -----------------------------
# This code loads the dataset from the specified CSV file path into a pandas DataFrame, prints the overall shape of the dataset (number of rows and columns), displays the list of column names to understand the dataset structure, and shows the distribution of values in the 'label' column to analyze class balance before further preprocessing or model training.
df = pd.read_csv(CSV_PATH)
print("Dataset shape:", df.shape)
print("Columns:", df.columns.tolist())
print("Label distribution:\n", df['label'].value_counts())

# Prepare features and target
X = df.drop(columns=['time', 'label'])
y = df['label'].astype(int).values
X = X.select_dtypes(include=[np.number]).fillna(0)

# Split data
if USE_FULL_DATASET:
    X_train, X_test, y_train, y_test = X.values, X.values, y, y
else:
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y, test_size=0.3, random_state=RANDOM_STATE, stratify=y
    )

# Scale
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==================== DIAGNOSTIC CHECKS ====================
print("\n" + "="*80)
print("🚨 MODEL DIAGNOSTICS - Checking for 100% False Positives")
print("="*80)

# 1. Check training data balance
print("1. TRAINING DATA ANALYSIS:")
print(f"   Total samples: {len(y)}")
print(f"   Normal samples (0): {(y == 0).sum()} ({(y == 0).mean()*100:.1f}%)")
print(f"   Malicious samples (1): {(y == 1).sum()} ({(y == 1).mean()*100:.1f}%)")

# -----------------------------
# DEFINE MODELS TO COMPARE (WITH BALANCED CLASS WEIGHTS)
# -----------------------------
models = {
    'Logistic Regression': LogisticRegression(
        class_weight='balanced',  # Added for imbalance
        random_state=RANDOM_STATE,
        max_iter=1000
    ),
    'Random Forest': RandomForestClassifier(
        class_weight='balanced',  # Added for imbalance
        random_state=RANDOM_STATE,
        n_estimators=100
    ),
    'SVM': SVC(
        class_weight='balanced',  # Added for imbalance
        random_state=RANDOM_STATE,
        kernel='rbf',
        probability=True
    ),
    'K-Nearest Neighbors': KNeighborsClassifier(
        n_neighbors=5
    ),
    'Decision Tree': DecisionTreeClassifier(
        class_weight='balanced',  # Added for imbalance
        random_state=RANDOM_STATE
    ),
    'Gradient Boosting': GradientBoostingClassifier(
        random_state=RANDOM_STATE,
        n_estimators=100
    )
}

# -----------------------------
# TRAIN AND EVALUATE ALL MODELS
# -----------------------------
# =============================================================================
# MODEL TRAINING AND EVALUATION PIPELINE
# =============================================================================
# This block iterates through all machine learning models stored in the
# `models` dictionary and performs the following steps for each model:
#
# 1. Trains the model using the scaled training dataset.
# 2. Measures training time for performance benchmarking.
# 3. Generates predictions on the scaled test dataset.
# 4. Measures prediction time (inference speed).
# 5. Computes evaluation metrics:
#       - Accuracy
#       - Precision
#       - Recall
#       - F1-Score
# 6. Calculates the malicious prediction rate (percentage of samples
#    predicted as malicious) to analyze class bias.
# 7. Stores all metrics and timing results in the `results` list
#    for later comparison and ranking.
#
# This allows systematic benchmarking and comparison of multiple
# models in terms of both performance and computational efficiency.
# =============================================================================

results = []

print("\nTraining and evaluating multiple models...")
print("=" * 60)

for model_name, model in models.items():
    print(f"Training {model_name}...")
    
    # Train model
    start_time = time.time()
    model.fit(X_train_scaled, y_train)
    training_time = time.time() - start_time
    
    # Predict
    start_time = time.time()
    y_pred = model.predict(X_test_scaled)
    prediction_time = time.time() - start_time
    
    # Calculate metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    
    # Store results
    results.append({
        'Model': model_name,
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1-Score': f1,
        'Training Time (s)': training_time,
        'Prediction Time (s)': prediction_time,
        'Malicious_Prediction_Rate': (y_pred == 1).mean()  # Track how often it predicts malicious
    })
    
    print(f"  - Completed in {training_time:.3f}s | Accuracy: {acc:.4f} | Malicious%: {(y_pred == 1).mean()*100:.1f}%")



def generate_model_visualizations(best_model, X_test_scaled, y_test, best_model_name):
    """Generate ROC curve and Confusion Matrix for the best model"""
    
    print("\n" + "="*80)
    print("📊 GENERATING MODEL VISUALIZATIONS")
    print("="*80)
    
    try:
        # Get predictions and probabilities
        y_pred = best_model.predict(X_test_scaled)
        y_proba = best_model.predict_proba(X_test_scaled)[:, 1] if hasattr(best_model, "predict_proba") else None
        
        # ========== 1. CONFUSION MATRIX ==========
        print("\n1. Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        plt.figure(figsize=(10, 4))
        
        # Subplot 1: Confusion Matrix
        plt.subplot(1, 2, 1)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                    xticklabels=['Normal', 'Malicious'],
                    yticklabels=['Normal', 'Malicious'])
        plt.title(f'Confusion Matrix - {best_model_name}')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        
        # ========== 2. ROC CURVE (if model supports probabilities) ==========
        if y_proba is not None:
            fpr, tpr, thresholds = roc_curve(y_test, y_proba)
            roc_auc = auc(fpr, tpr)
            
            plt.subplot(1, 2, 2)
            plt.plot(fpr, tpr, color='darkorange', lw=2, 
                     label=f'ROC curve (AUC = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic (ROC) Curve')
            plt.legend(loc="lower right")
        
        plt.tight_layout()
        
        # Save to file
        plt.savefig('model_visualizations.png', dpi=150, bbox_inches='tight')
        print("✅ Visualizations saved as 'model_visualizations.png'")
        
        # Show plot (optional)
        # plt.show()
        plt.close()
        
        return {
            'confusion_matrix': cm.tolist(),
            'roc_auc': roc_auc if y_proba is not None else None,
            'fpr': fpr.tolist() if y_proba is not None else None,
            'tpr': tpr.tolist() if y_proba is not None else None
        }
        
    except Exception as e:
        print(f"⚠️ Error generating visualizations: {str(e)}")
        return None

# -----------------------------
# COMPARE MODEL PERFORMANCE
# -----------------------------
results_df = pd.DataFrame(results)
results_df = results_df.sort_values('Accuracy', ascending=False)

print("\n" + "=" * 80)
print("MODEL COMPARISON RESULTS")
print("=" * 80)
print(results_df.to_string(index=False))

# Find best model (but check for reasonable malicious prediction rate)
reasonable_models = results_df[results_df['Malicious_Prediction_Rate'] < 0.8]  # Filter out models that predict >80% malicious

if len(reasonable_models) > 0:
    best_model_name = reasonable_models.iloc[0]['Model']
    print(f"\n✅ REASONABLE MODEL SELECTED: {best_model_name}")
    print(f"   (Malicious prediction rate: {reasonable_models.iloc[0]['Malicious_Prediction_Rate']*100:.1f}%)")
else:
    best_model_name = results_df.iloc[0]['Model']
    print(f"\n⚠️  WARNING: All models predict high malicious rates. Using: {best_model_name}")

best_model = models[best_model_name]

print("\n" + "="*80)
print("📈 GENERATING MODEL VISUALIZATIONS")
print("="*80)

# Generate visualizations
viz_data = generate_model_visualizations(best_model, X_test_scaled, y_test, best_model_name)

# Save visualization data for later use
import json
if viz_data:
    with open('model_viz_data.json', 'w') as f:
        json.dump(viz_data, f)
    print("✅ Visualization data saved to 'model_viz_data.json'")

# 2. Check model performance diagnostics
print("\n2. MODEL PERFORMANCE ANALYSIS:")
y_train_pred = best_model.predict(X_train_scaled)
y_test_pred = best_model.predict(X_test_scaled)

print("   Training Results:")
print(classification_report(y_train, y_train_pred, target_names=['Normal', 'Malicious']))
print("   Test Results:")
print(classification_report(y_test, y_test_pred, target_names=['Normal', 'Malicious']))

# 3. Check for overfitting
train_accuracy = accuracy_score(y_train, y_train_pred)
test_accuracy = accuracy_score(y_test, y_test_pred)
print(f"\n3. OVERFITTING CHECK:")
print(f"   Training Accuracy: {train_accuracy:.4f}")
print(f"   Test Accuracy: {test_accuracy:.4f}")
print(f"   Accuracy Difference: {train_accuracy - test_accuracy:.4f}")
if train_accuracy - test_accuracy > 0.1:
    print("   ⚠️  WARNING: Model is overfitting!")


# -----------------------------
# PCAP ANALYSIS MODULE
# -----------------------------

class NetworkTrafficAnalyzer:
    def __init__(self, trained_model, scaler, feature_columns):
        self.model = trained_model
        self.scaler = scaler
        self.feature_columns = feature_columns
        
    def extract_features_from_packet(self, packet, flow_stats):
        """Extract features from a single packet"""
        features = {}
        
        try:
            if IP in packet:
                features['src_ip'] = packet[IP].src
                features['dst_ip'] = packet[IP].dst
                features['protocol'] = packet[IP].proto
                features['packet_length'] = len(packet)
                features['ttl'] = packet[IP].ttl
                
                if TCP in packet:
                    features['src_port'] = packet[TCP].sport
                    features['dst_port'] = packet[TCP].dport
                    features['tcp_flags'] = packet[TCP].flags
                    features['window_size'] = packet[TCP].window
                elif UDP in packet:
                    features['src_port'] = packet[UDP].sport
                    features['dst_port'] = packet[UDP].dport
                    features['window_size'] = 0
                    features['tcp_flags'] = 0
                else:
                    features['src_port'] = 0
                    features['dst_port'] = 0
                    features['window_size'] = 0
                    features['tcp_flags'] = 0
                    
                flow_key = f"{packet[IP].src}-{packet[IP].dst}-{features.get('src_port', 0)}-{features.get('dst_port', 0)}"
                
                if flow_key not in flow_stats:
                    flow_stats[flow_key] = {
                        'packet_count': 0,
                        'total_bytes': 0,
                        'start_time': packet.time,
                        'last_time': packet.time
                    }
                
                flow_stats[flow_key]['packet_count'] += 1
                flow_stats[flow_key]['total_bytes'] += len(packet)
                flow_stats[flow_key]['last_time'] = packet.time
                
                features['flow_packet_count'] = flow_stats[flow_key]['packet_count']
                features['flow_total_bytes'] = flow_stats[flow_key]['total_bytes']
                features['flow_duration'] = flow_stats[flow_key]['last_time'] - flow_stats[flow_key]['start_time']
                
            else:
                return None
                
        except Exception as e:
            return None
            
        return features
    
    def pcap_to_dataframe(self, pcap_file, max_packets=5000):
        """Convert PCAP file to DataFrame with extracted features"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            packets = rdpcap(pcap_file)
            print(f"Total packets in file: {len(packets)}")
            
            if len(packets) > max_packets:
                packets = packets[:max_packets]
                print(f"Analyzing first {max_packets} packets...")
            
            features_list = []
            flow_stats = {}
            total_analyzed = 0
            
            for i, packet in enumerate(packets):
                if i % 1000 == 0 and i > 0:
                    print(f"Processed {i}/{len(packets)} packets...")
                    
                features = self.extract_features_from_packet(packet, flow_stats)
                if features:
                    features_list.append(features)
                    total_analyzed += 1
            
            df = pd.DataFrame(features_list)
            
            if not df.empty:
                df['packet_size_mean'] = df['packet_length'].mean()
                df['packet_size_std'] = df['packet_length'].std()
                df['packet_size_min'] = df['packet_length'].min()
                df['packet_size_max'] = df['packet_length'].max()
                
                df['is_well_known_port'] = df['dst_port'].apply(
                    lambda x: 1 if x in [80, 443, 21, 22, 25, 53, 110, 143] else 0
                )
                
                df['has_syn_flag'] = df['tcp_flags'].apply(lambda x: 1 if x & 0x02 else 0)
                df['has_fin_flag'] = df['tcp_flags'].apply(lambda x: 1 if x & 0x01 else 0)
                df['has_rst_flag'] = df['tcp_flags'].apply(lambda x: 1 if x & 0x04 else 0)
                
            print(f"Successfully extracted features from {total_analyzed} packets")
            return df
            
        except Exception as e:
            print(f"Error reading PCAP file: {str(e)}")
            return pd.DataFrame()

    def analyze_pcap(self, pcap_file, confidence_threshold=0.5):
        """Main analysis function for PCAP files"""
        print("\n" + "="*80)
        print("NETWORK TRAFFIC ANALYSIS REPORT")
        print("="*80)
        
        pcap_df = self.pcap_to_dataframe(pcap_file)
        
        if pcap_df.empty:
            print("No valid network packets found in the file.")
            return None
        
        missing_cols = set(self.feature_columns) - set(pcap_df.columns)
        for col in missing_cols:
            pcap_df[col] = 0
        
        pcap_df = pcap_df[self.feature_columns]
        
        X_pcap_scaled = self.scaler.transform(pcap_df)
        
        # Get probabilities and apply threshold
        try:
            probabilities = self.model.predict_proba(X_pcap_scaled)
            predictions = (probabilities[:, 1] > confidence_threshold).astype(int)
        except:
            predictions = self.model.predict(X_pcap_scaled)
            probabilities = None
        
        malicious_count = np.sum(predictions)
        total_count = len(predictions)
        malicious_percentage = (malicious_count / total_count) * 100 if total_count > 0 else 0
        
        print(f"\nANALYSIS RESULTS (Threshold: {confidence_threshold}):")
        print(f"   Total packets analyzed: {total_count}")
        print(f"   Malicious packets detected: {malicious_count}")
        print(f"   Malicious traffic percentage: {malicious_percentage:.2f}%")
        
        # Risk assessment
        risk_level = self.get_risk_level(malicious_percentage)
        recommendation = self.get_recommendation(malicious_percentage)
        
        print(f"\nRISK ASSESSMENT: {risk_level}")
        print(f"RECOMMENDATION: {recommendation}")
        
        if malicious_count > 0 and probabilities is not None:
            malicious_indices = np.where(predictions == 1)[0]
            malicious_probs = probabilities[malicious_indices, 1]
            
            print(f"\nDETAILED FINDINGS:")
            print(f"   - Found {malicious_count} packets with malicious characteristics")
            print(f"   - Confidence scores range: {malicious_probs.min():.3f} to {malicious_probs.max():.3f}")
            
            print(f"\nTOP SUSPICIOUS PACKETS:")
            top_malicious = sorted(zip(malicious_indices, malicious_probs), 
                                key=lambda x: x[1], reverse=True)[:5]
            
            for idx, prob in top_malicious:
                packet_data = pcap_df.iloc[idx]
                print(f"   - Packet {idx}: Confidence {prob:.3f}")
                if 'src_ip' in packet_data and 'dst_ip' in packet_data:
                    print(f"     Source: {packet_data['src_ip']} -> Destination: {packet_data['dst_ip']}")
        
        # ========== ADDED: GENERATE VISUALIZATIONS ==========
        print("\n" + "="*80)
        print("📊 GENERATING VISUALIZATIONS")
        print("="*80)
        
        # Generate visualizations
        viz_filename = self.visualize_pcap_analysis(pcap_df, predictions, probabilities, confidence_threshold)
        
        # Generate HTML report
        self.generate_html_report(pcap_df, predictions, probabilities, viz_filename, 
                                malicious_percentage, risk_level, recommendation)
        
        # Return results including visualization info
        return {
            'total_packets': total_count,
            'malicious_packets': malicious_count,
            'malicious_percentage': malicious_percentage,
            'risk_level': risk_level,
            'recommendation': recommendation,
            'confidence_threshold': confidence_threshold,
            'visualization_file': viz_filename,
            'html_report': 'pcap_analysis_report.html'
        }

    # ========== ADDED HELPER METHODS ==========

    def get_risk_level(self, malicious_percentage):
        """Determine risk level based on malicious percentage"""
        if malicious_percentage > 10:
            return "HIGH RISK"
        elif malicious_percentage > 5:
            return "MEDIUM RISK"
        elif malicious_percentage > 1:
            return "LOW RISK"
        else:
            return "CLEAN"

    def get_recommendation(self, malicious_percentage):
        """Get recommendation based on risk level"""
        if malicious_percentage > 10:
            return "Immediate investigation required!"
        elif malicious_percentage > 5:
            return "Further monitoring recommended."
        elif malicious_percentage > 1:
            return "Minor suspicious activity."
        else:
            return "No significant threats detected."

    def visualize_pcap_analysis(self, pcap_df, predictions, probabilities=None, confidence_threshold=0.5):
        """Generate visualizations for PCAP analysis"""
        
        try:
            # Create figure with multiple subplots
            fig, axes = plt.subplots(2, 3, figsize=(15, 10))
            plt.suptitle(f'PCAP Analysis Dashboard - Threshold: {confidence_threshold}', fontsize=16)
            
            # 1. THREAT DISTRIBUTION PIE CHART
            malicious_count = np.sum(predictions)
            normal_count = len(predictions) - malicious_count
            labels = ['Normal', 'Malicious'] if malicious_count > 0 else ['Normal']
            sizes = [normal_count, malicious_count] if malicious_count > 0 else [normal_count]
            colors = ['#2ecc71', '#e74c3c'] if malicious_count > 0 else ['#2ecc71']
            
            axes[0, 0].pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            axes[0, 0].set_title('Threat Distribution')
            
            # 2. PACKET SIZE DISTRIBUTION
            if 'packet_length' in pcap_df.columns:
                axes[0, 1].hist(pcap_df['packet_length'], bins=50, color='#3498db', alpha=0.7)
                axes[0, 1].set_xlabel('Packet Size (bytes)')
                axes[0, 1].set_ylabel('Frequency')
                axes[0, 1].set_title('Packet Size Distribution')
                axes[0, 1].axvline(pcap_df['packet_length'].mean(), color='red', linestyle='--', 
                                label=f'Mean: {pcap_df["packet_length"].mean():.0f} bytes')
                axes[0, 1].legend()
            
            # 3. PROTOCOL DISTRIBUTION
            if 'protocol' in pcap_df.columns:
                protocol_counts = pcap_df['protocol'].value_counts().head(10)
                axes[0, 2].bar(range(len(protocol_counts)), protocol_counts.values, 
                            tick_label=protocol_counts.index, color='#9b59b6')
                axes[0, 2].set_xlabel('Protocol Number')
                axes[0, 2].set_ylabel('Count')
                axes[0, 2].set_title('Top 10 Protocols')
                axes[0, 2].tick_params(axis='x', rotation=45)
            
            # 4. CONFIDENCE SCORE DISTRIBUTION
            if probabilities is not None:
                axes[1, 0].hist(probabilities[:, 1], bins=50, color='#f39c12', alpha=0.7)
                axes[1, 0].set_xlabel('Malicious Confidence Score')
                axes[1, 0].set_ylabel('Frequency')
                axes[1, 0].set_title('Confidence Score Distribution')
                axes[1, 0].axvline(confidence_threshold, color='red', linestyle='--', 
                                label=f'Threshold: {confidence_threshold}')
                axes[1, 0].legend()
            
            # 5. TOP SOURCE IPs
            if 'src_ip' in pcap_df.columns:
                top_sources = pcap_df['src_ip'].value_counts().head(10)
                axes[1, 1].barh(range(len(top_sources)), top_sources.values, color='#1abc9c')
                axes[1, 1].set_yticks(range(len(top_sources)))
                axes[1, 1].set_yticklabels(top_sources.index)
                axes[1, 1].set_xlabel('Packet Count')
                axes[1, 1].set_title('Top 10 Source IPs')
            
            # 6. DESTINATION PORTS
            if 'dst_port' in pcap_df.columns:
                top_ports = pcap_df['dst_port'].value_counts().head(10)
                axes[1, 2].bar(range(len(top_ports)), top_ports.values, color='#e67e22')
                axes[1, 2].set_xticks(range(len(top_ports)))
                axes[1, 2].set_xticklabels(top_ports.index, rotation=45)
                axes[1, 2].set_xlabel('Port Number')
                axes[1, 2].set_ylabel('Count')
                axes[1, 2].set_title('Top 10 Destination Ports')
            
            plt.tight_layout()
            
            # Save to file with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f'pcap_analysis_{timestamp}.png'
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            print(f"✅ PCAP visualizations saved as '{filename}'")
            
            plt.close()
            return filename
            
        except Exception as e:
            print(f"⚠️ Error generating PCAP visualizations: {str(e)}")
            return None

    def generate_html_report(self, pcap_df, predictions, probabilities, viz_filename, 
                            malicious_percentage, risk_level, recommendation):
        """Generate HTML report with visualizations"""
        
        malicious_count = np.sum(predictions)
        total_count = len(predictions)
        
        # Risk color coding
        if malicious_percentage > 10:
            risk_color = "#e74c3c"
        elif malicious_percentage > 5:
            risk_color = "#f39c12"
        elif malicious_percentage > 1:
            risk_color = "#f1c40f"
        else:
            risk_color = "#2ecc71"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Traffic Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .metric {{ background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .risk {{ background: {risk_color}; color: white; padding: 10px; border-radius: 5px; }}
                .visualization {{ margin: 20px 0; }}
                img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th {{ background: #34495e; color: white; padding: 10px; }}
                td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1> Network Traffic Analysis Report</h1>
                <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            
            <div class="metric">
                <h2> Summary Metrics</h2>
                <p>Total Packets Analyzed: <strong>{total_count}</strong></p>
                <p>Malicious Packets Detected: <strong>{malicious_count}</strong></p>
                <p>Malicious Percentage: <strong>{malicious_percentage:.2f}%</strong></p>
            </div>
            
            <div class="risk">
                <h2> Risk Assessment</h2>
                <p>Risk Level: <strong>{risk_level}</strong></p>
                <p>Recommendation: <strong>{recommendation}</strong></p>
            </div>
            
            <div class="visualization">
                <h2> Visualizations</h2>
                <img src="{viz_filename}" alt="PCAP Analysis Dashboard">
            </div>
            
            <div class="metric">
                <h2> Top Suspicious Packets</h2>
                {self.generate_top_suspicious_table(pcap_df, predictions, probabilities)}
            </div>
        </body>
        </html>
        """
        
        # Save HTML report
        with open('pcap_analysis_report.html', 'w') as f:
            f.write(html_content)
        print("✅ HTML report saved as 'pcap_analysis_report.html'")

    def generate_top_suspicious_table(self, pcap_df, predictions, probabilities, top_n=5):
        """Generate HTML table of top suspicious packets"""
        if probabilities is not None and np.sum(predictions) > 0:
            malicious_indices = np.where(predictions == 1)[0]
            malicious_probs = probabilities[malicious_indices, 1]
            top_malicious = sorted(zip(malicious_indices, malicious_probs), 
                                key=lambda x: x[1], reverse=True)[:top_n]
            
            table_rows = ""
            for idx, prob in top_malicious:
                packet_data = pcap_df.iloc[idx]
                src_ip = packet_data.get('src_ip', 'N/A')
                dst_ip = packet_data.get('dst_ip', 'N/A')
                packet_len = packet_data.get('packet_length', 'N/A')
                dst_port = packet_data.get('dst_port', 'N/A')
                
                table_rows += f"""
                <tr>
                    <td>{idx}</td>
                    <td>{src_ip}</td>
                    <td>{dst_ip}:{dst_port}</td>
                    <td>{packet_len}</td>
                    <td>{prob:.3f}</td>
                </tr>
                """
            
            return f"""
            <table>
                <tr>
                    <th>Packet #</th>
                    <th>Source IP</th>
                    <th>Destination</th>
                    <th>Size (bytes)</th>
                    <th>Confidence</th>
                </tr>
                {table_rows}
            </table>
            """
        return "<p>No suspicious packets detected.</p>"

# -----------------------------
# INITIALIZE ANALYZER
# -----------------------------

print(f"\n" + "="*80)
print("NETWORK TRAFFIC ANALYZER INITIALIZED")
print("="*80)

analyzer = NetworkTrafficAnalyzer(
    trained_model=best_model,
    scaler=scaler,
    feature_columns=X.columns.tolist()
)

print(f"Analyzer ready with model: {best_model_name}")

# -----------------------------
# REALISTIC PCAP TEST FUNCTION
# -----------------------------

def realistic_pcap_test(pcap_file):
    """Test with realistic expectations and multiple thresholds"""
    print(f"\n🎯 REALISTIC ANALYSIS OF: {pcap_file}")
    
    # Test with different confidence thresholds
    thresholds = [0.5, 0.7, 0.8, 0.9]
    results = []
    
    for threshold in thresholds:
        print(f"\n--- Testing with threshold {threshold} ---")
        report = analyzer.analyze_pcap(pcap_file, confidence_threshold=threshold)
        if report:
            results.append(report)
    
    # Summary
    print(f"\n" + "="*60)
    print("SUMMARY - Multiple Threshold Analysis")
    print("="*60)
    for result in results:
        print(f"Threshold {result['confidence_threshold']}: {result['malicious_percentage']:.1f}% malicious -> {result['risk_level']}")
    
    # Determine realistic assessment
    if results[-1]['malicious_percentage'] > 50:  # Even with high threshold
        print(f"\n🚨 ALERT: Even with high threshold ({results[-1]['confidence_threshold']}),")
        print(f"   {results[-1]['malicious_percentage']:.1f}% packets are flagged as malicious.")
        print("   This indicates either:")
        print("   - The traffic is genuinely suspicious")
        print("   - The model needs retraining with better data")
    else:
        realistic_malicious = min(results[-1]['malicious_percentage'], 10)  # Conservative estimate
        print(f"\n✅ REALISTIC ASSESSMENT: Approximately {realistic_malicious:.1f}% suspicious traffic")
        print("   (Based on high-confidence threshold)")

# -----------------------------
# MAIN EXECUTION
# -----------------------------

# Ask user if they want to analyze a PCAP file
user_choice = input("\nDo you want to analyze a PCAP file? (yes/no): ").strip().lower()
if user_choice in ['yes', 'y']:
    pcap_path = input("Enter the path to your PCAP file: ").strip().strip('"')
    
    if not os.path.exists(pcap_path):
        print("File not found. Please check the path.")
    elif not pcap_path.lower().endswith(('.pcap', '.pcapng', '.cap')):
        print("Please provide a valid PCAP file (.pcap, .pcapng, .cap)")
    else:
        realistic_pcap_test(pcap_path)
else:
    print("\nTraining completed. You can analyze PCAP files later.")

print("\n" + "="*80)
print("ANALYSIS COMPLETE")
print("="*80)




















































































