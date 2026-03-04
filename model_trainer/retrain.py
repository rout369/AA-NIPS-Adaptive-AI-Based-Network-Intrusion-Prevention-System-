#!/usr/bin/env python3
"""
Retrain script - Combines original data with featured feedback to improve models
Requires minimum 4500 feedback samples for meaningful retraining
"""

import argparse
import warnings
import json
import os
import numpy as np
import pandas as pd
import joblib
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score

warnings.filterwarnings("ignore")

# Constants
MIN_SAMPLES = 4500
ORIGINAL_DATA_PATH = 'network_traffic.csv'
FEATURED_FEEDBACK_PATH = 'feedback/feedback_with_features.jsonl'
MODELS_DIR = 'models'

def log(msg, always=False):
    """Print message"""
    print(msg)

def load_original_data():
    """Load original training data"""
    log("\n📂 Loading original training data...")
    df = pd.read_csv(ORIGINAL_DATA_PATH)
    log(f"   Original samples: {len(df)}")
    
    # Prepare features and target
    X = df.drop(columns=['time', 'label'])
    y = df['label'].astype(int).values
    X = X.select_dtypes(include=[np.number]).fillna(0)
    
    feature_columns = X.columns.tolist()
    log(f"   Features: {len(feature_columns)}")
    
    return X.values, y, feature_columns

def load_featured_feedback():
    """Load feedback with actual feature vectors"""
    log("\n📝 Loading featured feedback data...")
    
    if not os.path.exists(FEATURED_FEEDBACK_PATH):
        log("   No featured feedback found")
        return None, None
    
    feedback_features = []
    feedback_labels = []
    reason_counts = {'false_positive': 0, 'missed_attack': 0, 'correct': 0}
    
    with open(FEATURED_FEEDBACK_PATH, 'r') as f:
        for line in f:
            try:
                fb = json.loads(line)
                features = fb['features']
                reason = fb['reason']
                
                # Convert reason to label
                if reason == 'false_positive':
                    # ML said malicious (1) but should be normal (0)
                    label = 0
                    reason_counts['false_positive'] += 1
                elif reason == 'missed_attack':
                    # ML said normal (0) but should be malicious (1)
                    label = 1
                    reason_counts['missed_attack'] += 1
                elif reason == 'correct':
                    # ML was correct, skip for training (or could use as reinforcement)
                    continue
                else:
                    continue
                
                # Convert features to list in correct order
                feature_vector = []
                for col in ['source_ip_int', 'destination_ip_int', 'source_port', 
                           'destination_port', 'protocol', 'duration', 'packet_count',
                           'bytes_sent', 'bytes_received', 'bytes_per_packet']:
                    feature_vector.append(float(features.get(col, 0)))
                
                feedback_features.append(feature_vector)
                feedback_labels.append(label)
                
            except Exception as e:
                log(f"   ⚠️ Error parsing feedback: {e}")
                continue
    
    if not feedback_features:
        log("   No usable feedback samples")
        return None, None
    
    log(f"   Total usable feedback: {len(feedback_features)}")
    log(f"   • False positives: {reason_counts['false_positive']}")
    log(f"   • Missed attacks:  {reason_counts['missed_attack']}")
    
    return np.array(feedback_features), np.array(feedback_labels)

def train_models(X_train, y_train, X_test, y_test, feature_columns):
    """Train all 6 models and return them with accuracies"""
    log("\n🔄 Training models...")
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Define models
    models = {
        'random_forest': RandomForestClassifier(
            class_weight='balanced', 
            random_state=42, 
            n_estimators=100,
            n_jobs=-1
        ),
        'gradient_boost': GradientBoostingClassifier(
            random_state=42, 
            n_estimators=100
        ),
        'svm': SVC(
            class_weight='balanced', 
            random_state=42, 
            kernel='rbf', 
            probability=True,
            cache_size=1000
        ),
        'logistic': LogisticRegression(
            class_weight='balanced', 
            random_state=42, 
            max_iter=1000,
            n_jobs=-1
        ),
        'decision_tree': DecisionTreeClassifier(
            class_weight='balanced', 
            random_state=42
        ),
        'knn': KNeighborsClassifier(
            n_neighbors=5,
            n_jobs=-1
        )
    }
    
    trained_models = {}
    accuracies = {}
    
    for name, model in models.items():
        log(f"   Training {name}...")
        model.fit(X_train_scaled, y_train)
        trained_models[name] = model
        
        y_pred = model.predict(X_test_scaled)
        acc = accuracy_score(y_test, y_pred)
        accuracies[name] = acc
        log(f"      Accuracy: {acc:.4f}")
    
    return trained_models, accuracies, scaler

def save_models(models, accuracies, scaler, feature_columns):
    """Save all trained models and metadata"""
    log("\n💾 Saving updated models...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    # Save individual models
    for name, model in models.items():
        model_path = os.path.join(MODELS_DIR, f'{name}.pkl')
        joblib.dump(model, model_path)
        log(f"   ✅ Saved {name}")
    
    # Save scaler
    joblib.dump(scaler, os.path.join(MODELS_DIR, 'scaler.pkl'))
    
    # Save feature columns
    joblib.dump(feature_columns, os.path.join(MODELS_DIR, 'feature_columns.pkl'))
    
    # Calculate and save weights
    total_acc = sum(accuracies.values())
    weights = {name: acc/total_acc for name, acc in accuracies.items()}
    joblib.dump(weights, os.path.join(MODELS_DIR, 'model_weights.pkl'))
    
    # Save best model info
    best_model = max(accuracies, key=accuracies.get)
    best_model_info = {
        'name': best_model,
        'accuracy': accuracies[best_model],
        'display_name': best_model.replace('_', ' ').title()
    }
    joblib.dump(best_model_info, os.path.join(MODELS_DIR, 'best_model_info.pkl'))
    
    log(f"\n🏆 Best model: {best_model} ({accuracies[best_model]:.1%})")
    
    return best_model, accuracies[best_model]

def main():
    parser = argparse.ArgumentParser(description='Retrain ML models with feedback')
    parser.add_argument('--featured', action='store_true', help='Use featured feedback')
    parser.add_argument('--force', action='store_true', help='Force retraining even if below minimum')
    args = parser.parse_args()
    
    log("\n" + "="*60, always=True)
    log("🔄 RETRAINING MODELS WITH FEEDBACK", always=True)
    log("="*60, always=True)
    
    # Load original data
    X_orig, y_orig, feature_columns = load_original_data()
    
    # Load featured feedback
    X_fb, y_fb = load_featured_feedback()
    
    # Check if we have enough feedback
    if X_fb is not None:
        total_feedback = len(X_fb)
        log(f"\n📊 Feedback samples: {total_feedback}")
        
        if total_feedback < MIN_SAMPLES and not args.force:
            log(f"\n⚠️  Need {MIN_SAMPLES - total_feedback} more samples for retraining", always=True)
            log(f"   Use --force to retrain anyway", always=True)
            return
        
        # Combine datasets
        log("\n🔄 Combining datasets...")
        X_combined = np.vstack([X_orig, X_fb])
        y_combined = np.concatenate([y_orig, y_fb])
        log(f"   Total samples: {len(X_combined)}")
        log(f"   • Original: {len(X_orig)}")
        log(f"   • Feedback: {len(X_fb)}")
    else:
        log("\n📊 Using only original data")
        X_combined = X_orig
        y_combined = y_orig
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y_combined, test_size=0.3, random_state=42, stratify=y_combined
    )
    
    # Train models
    models, accuracies, scaler = train_models(X_train, y_train, X_test, y_test, feature_columns)
    
    # Save models
    best_model, best_acc = save_models(models, accuracies, scaler, feature_columns)
    
    log("\n" + "="*60, always=True)
    log("✅ RETRAINING COMPLETE", always=True)
    log("="*60, always=True)

if __name__ == '__main__':
    main()