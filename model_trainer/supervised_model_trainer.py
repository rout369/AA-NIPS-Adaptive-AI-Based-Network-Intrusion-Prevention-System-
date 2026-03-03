# ============================================
# PHASE 3: PRODUCTION-READY MODEL TRAINER
# 5-Class Classification on Balanced NSL-KDD
# With all original features + enhancements
# ============================================

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import time
import warnings
import os
import psutil
import json
import joblib
from collections import Counter
from datetime import datetime
import io
import base64

from sklearn.metrics import (classification_report, confusion_matrix, 
                             accuracy_score, f1_score, precision_score,
                             recall_score, roc_curve, auc, roc_auc_score)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.utils import class_weight

# Core models
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.svm import SVC, LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.decomposition import PCA

# Boosting (with fallbacks)
try:
    import xgboost as xgb
    xgb_available = True
except ImportError:
    xgb_available = False
    print("⚠️ XGBoost not installed – skipping.")

try:
    import lightgbm as lgb
    lgb_available = True
except ImportError:
    lgb_available = False
    print("⚠️ LightGBM not installed – skipping.")

try:
    from catboost import CatBoostClassifier
    catboost_available = True
except ImportError:
    catboost_available = False
    print("⚠️ CatBoost not installed – skipping.")

# For SHAP analysis
try:
    import shap
    shap_available = True
    print("✅ SHAP installed - feature importance analysis available")
except ImportError:
    shap_available = False
    print("⚠️ SHAP not installed - install with: pip install shap")


# For PCAP analysis
try:
    import scapy.all as scapy
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    scapy_available = True
except ImportError:
    scapy_available = False
    print("⚠️ Scapy not installed – PCAP analysis disabled.")

warnings.filterwarnings('ignore')

print("=" * 80)
print("PHASE 3: PRODUCTION-READY MODEL TRAINER")
print("5-Class Classification on Balanced NSL-KDD")
print("=" * 80)

# Check memory
mem = psutil.virtual_memory()
print(f"System RAM: {mem.total / 1024**3:.1f} GB available")
if mem.total / 1024**3 < 6:
    print("⚠️ Low memory – models will use reduced complexity.")
print("=" * 80)

# Create models directory
os.makedirs("models", exist_ok=True)
print(f"\n📁 Models will be saved in: 'models/' folder")

# -------------------------------------------------------------------
# 1. LOAD BALANCED DATASET
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("📂 LOADING BALANCED DATASET")
print("=" * 80)

try:
    # Load balanced training data
    X_train = np.load('../dataset_artifacts/X_train_bal.npy', allow_pickle=True)
    y_train = np.load('../dataset_artifacts/y_train_bal.npy', allow_pickle=True)
    
    # Load validation data (real, untouched)
    X_val = np.load('../dataset_artifacts/X_val_raw.npy', allow_pickle=True)
    y_val = np.load('../dataset_artifacts/y_val_raw.npy', allow_pickle=True)
    
    # Load preprocessors for test set
    scaler = joblib.load('../dataset_artifacts/scaler.pkl')
    encoders = joblib.load('../dataset_artifacts/encoders.pkl')
    feature_order = joblib.load('../dataset_artifacts/feature_order.pkl')
    
    print(f" Balanced training data: {X_train.shape[0]:,} samples, {X_train.shape[1]} features")
    print(f" Validation data (real): {X_val.shape[0]:,} samples")
    print(f" Preprocessors loaded successfully")
    
except FileNotFoundError as e:
    print(f"❌ Error: {e}")
    print("Please run Phase 2 first to generate dataset artifacts.")
    exit()

# -------------------------------------------------------------------
# 2. ENCODE LABELS
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("🏷️ LABEL ENCODING")
print("=" * 80)

le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_val_enc = le.transform(y_val)
class_names = le.classes_

print(f"Classes: {list(class_names)}")
for i, name in enumerate(class_names):
    count_train = np.sum(y_train_enc == i)
    count_val = np.sum(y_val_enc == i)
    print(f"  {i}: {name} - Train: {count_train:,}, Val: {count_val:,}")

# Save class names for later use
joblib.dump(class_names, 'models/class_names.pkl')
print(f"\n✅ Class names saved to 'models/class_names.pkl'")

# -------------------------------------------------------------------
# 3. DIAGNOSTIC CHECKS
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("🔍 DIAGNOSTIC CHECKS")
print("=" * 80)

# Class balance check
print("\nTraining Data Balance:")
for i, name in enumerate(class_names):
    pct = (np.sum(y_train_enc == i) / len(y_train_enc)) * 100
    print(f"  {name}: {pct:.2f}%")

# Check for extreme imbalance
if np.min([np.sum(y_train_enc == i) for i in range(len(class_names))]) < 100:
    print("⚠️ Warning: Some classes have very few samples!")

# -------------------------------------------------------------------
# 4. DEFINE CPU-OPTIMIZED MODELS
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" DEFINING MODELS")
print("=" * 80)

models = {}

# Core models (always available)
models['Random Forest'] = RandomForestClassifier(
    n_estimators=50, max_depth=15, random_state=42, n_jobs=-1,
    class_weight='balanced'
)

models['Decision Tree'] = DecisionTreeClassifier(
    max_depth=15, random_state=42,
    class_weight='balanced'
)

models['Logistic Regression'] = LogisticRegression(
    max_iter=1000, random_state=42, n_jobs=-1,
    class_weight='balanced'
)

models['Linear SVM'] = LinearSVC(
    C=1.0, max_iter=1000, random_state=42, dual=False,
    class_weight='balanced'
)

models['KNN'] = KNeighborsClassifier(
    n_neighbors=3, n_jobs=-1
)

models['Naive Bayes'] = GaussianNB()

models['Neural Network'] = MLPClassifier(
    hidden_layer_sizes=(50, 25), activation='relu',
    max_iter=200, random_state=42
)

models['Gradient Boosting'] = GradientBoostingClassifier(
    n_estimators=50, max_depth=4, learning_rate=0.1,
    random_state=42
)

# Boosting models (if available)
if xgb_available:
    models['XGBoost'] = xgb.XGBClassifier(
        n_estimators=50, max_depth=4, learning_rate=0.1,
        random_state=42, use_label_encoder=False,
        eval_metric='mlogloss', n_jobs=-1
    )

if lgb_available:
    models['LightGBM'] = lgb.LGBMClassifier(
        n_estimators=50, max_depth=4, learning_rate=0.1,
        random_state=42, n_jobs=-1, verbose=-1,
        class_weight='balanced'
    )

if catboost_available:
    models['CatBoost'] = CatBoostClassifier(
        iterations=50, depth=4, learning_rate=0.1,
        random_state=42, verbose=0, thread_count=-1
    )

print(f"\n Loaded {len(models)} models for training")

# -------------------------------------------------------------------
# 5. TRAIN AND EVALUATE ALL MODELS
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" TRAINING MODELS (This may take 15-25 minutes)")
print("=" * 80)

results = []
predictions = {}
training_times = {}
model_accuracies = {}

for name, model in models.items():
    print(f"\n▶ Training {name}...")
    print("-" * 60)
    
    start = time.time()
    try:
        # Train model
        model.fit(X_train, y_train_enc)
        elapsed = time.time() - start
        training_times[name] = elapsed
        
        # Predict on validation
        y_pred = model.predict(X_val)
        predictions[name] = y_pred
        
        # Calculate metrics
        acc = accuracy_score(y_val_enc, y_pred)
        f1_macro = f1_score(y_val_enc, y_pred, average='macro')
        f1_weighted = f1_score(y_val_enc, y_pred, average='weighted')
        f1_per_class = f1_score(y_val_enc, y_pred, average=None)
        
        # Store for weighting
        model_accuracies[name] = acc
        
        # Store results
        result = {
            'Model': name,
            'Accuracy': round(acc, 4),
            'F1_Macro': round(f1_macro, 4),
            'F1_Weighted': round(f1_weighted, 4),
            'Time_sec': round(elapsed, 2)
        }
        
        # Add per-class F1
        for i, cls in enumerate(class_names):
            result[f'F1_{cls}'] = round(f1_per_class[i], 4)
        
        results.append(result)
        
        # Print progress
        print(f"   Accuracy: {acc:.4f}")
        print(f"   F1 Macro: {f1_macro:.4f}")
        print(f"   Time: {elapsed:.1f}s")
        
        # Print key per-class F1
        u2r_idx = list(class_names).index('U2R') if 'U2R' in class_names else -1
        r2l_idx = list(class_names).index('R2L') if 'R2L' in class_names else -1
        
        if u2r_idx >= 0:
            print(f"   U2R F1: {f1_per_class[u2r_idx]:.4f}")
        if r2l_idx >= 0:
            print(f"   R2L F1: {f1_per_class[r2l_idx]:.4f}")
        
        # Save model immediately
        clean_name = name.lower().replace(' ', '_')
        model_path = f'models/{clean_name}.pkl'
        joblib.dump(model, model_path)
        print(f"  💾 Model saved: {model_path}")
        
    except Exception as e:
        print(f"  ❌ Error: {str(e)[:100]}")
        continue


# -------------------------------------------------------------------
# SHAP ANALYSIS FUNCTION
# -------------------------------------------------------------------
def analyze_shap(model, X_train_sample, X_val_sample, feature_names, class_names, model_name):
    """Generate SHAP explanations for model predictions"""
    
    print(f"\n🔍 Running SHAP analysis for {model_name}...")
    
    try:
        # Create SHAP explainer based on model type
        if 'XGBoost' in model_name or 'Random Forest' in model_name or 'Decision Tree' in model_name:
            # Tree-based models
            explainer = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(X_val_sample)
            
            # Summary plot - overall feature importance
            plt.figure(figsize=(12, 8))
            shap.summary_plot(shap_values, X_val_sample, feature_names=feature_names, 
                            class_names=class_names, show=False)
            plt.tight_layout()
            plt.savefig(f'shap_summary_{model_name.lower().replace(" ", "_")}.png', dpi=150, bbox_inches='tight')
            plt.show()
            
            # Bar plot - mean absolute SHAP values
            plt.figure(figsize=(10, 6))
            shap.summary_plot(shap_values, X_val_sample, feature_names=feature_names, 
                            plot_type="bar", class_names=class_names, show=False)
            plt.tight_layout()
            plt.savefig(f'shap_bar_{model_name.lower().replace(" ", "_")}.png', dpi=150, bbox_inches='tight')
            plt.show()
            
            # For U2R and R2L classes specifically (if they exist)
            u2r_idx = list(class_names).index('U2R') if 'U2R' in class_names else -1
            r2l_idx = list(class_names).index('R2L') if 'R2L' in class_names else -1
            
            if u2r_idx >= 0:
                plt.figure(figsize=(10, 6))
                shap.waterfall_plot(shap.Explanation(values=shap_values[u2r_idx][0], 
                                                    base_values=explainer.expected_value[u2r_idx],
                                                    data=X_val_sample[0],
                                                    feature_names=feature_names))
                plt.title(f'SHAP Waterfall for U2R Prediction - {model_name}')
                plt.tight_layout()
                plt.savefig(f'shap_waterfall_u2r_{model_name.lower().replace(" ", "_")}.png', dpi=150)
                plt.show()
            
        elif 'Linear' in model_name or 'Logistic' in model_name:
            # Linear models
            explainer = shap.LinearExplainer(model, X_train_sample)
            shap_values = explainer.shap_values(X_val_sample)
            
            plt.figure(figsize=(10, 6))
            shap.summary_plot(shap_values, X_val_sample, feature_names=feature_names, 
                            class_names=class_names, show=False)
            plt.tight_layout()
            plt.savefig(f'shap_linear_{model_name.lower().replace(" ", "_")}.png', dpi=150)
            plt.show()
            
        else:
            # Fallback for other models
            explainer = shap.KernelExplainer(model.predict_proba, X_train_sample[:100])
            shap_values = explainer.shap_values(X_val_sample[:50])
            
            plt.figure(figsize=(10, 6))
            shap.summary_plot(shap_values, X_val_sample[:50], feature_names=feature_names, 
                            class_names=class_names, show=False)
            plt.tight_layout()
            plt.savefig(f'shap_kernel_{model_name.lower().replace(" ", "_")}.png', dpi=150)
            plt.show()
        
        print(f"✅ SHAP analysis completed for {model_name}")
        return True
        
    except Exception as e:
        print(f"⚠️ SHAP analysis failed: {str(e)}")
        return False

# -------------------------------------------------------------------
# 6. COMPARE RESULTS
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" MODEL COMPARISON RESULTS")
print("=" * 80)

results_df = pd.DataFrame(results)
results_df = results_df.sort_values('F1_Macro', ascending=False).reset_index(drop=True)

print("\n", results_df.to_string(index=False))

# Save results
results_df.to_csv('phase3_results.csv', index=False)
print("\n✅ Results saved to 'phase3_results.csv'")

# -------------------------------------------------------------------
# 7. IDENTIFY BEST MODEL
# -------------------------------------------------------------------
best_model_name = results_df.iloc[0]['Model']
best_model = models[best_model_name]
best_pred = predictions[best_model_name]

print(f"\n BEST MODEL: {best_model_name}")
print(f"   F1 Macro: {results_df.iloc[0]['F1_Macro']:.4f}")
print(f"   Accuracy: {results_df.iloc[0]['Accuracy']:.4f}")

# Save best model info
best_model_info = {
    'name': best_model_name.lower().replace(' ', '_'),
    'accuracy': results_df.iloc[0]['Accuracy'],
    'f1_macro': results_df.iloc[0]['F1_Macro'],
    'display_name': best_model_name
}
joblib.dump(best_model_info, 'models/best_model_info.pkl')
print("✅ Best model info saved")


# -------------------------------------------------------------------
# SHAP ANALYSIS FOR BEST MODEL
# -------------------------------------------------------------------
if shap_available:
    print("\n" + "=" * 80)
    print("🔍 GENERATING SHAP EXPLANATIONS FOR BEST MODEL")
    print("=" * 80)
    
    # Take samples for SHAP (to avoid memory issues)
    n_samples = min(100, len(X_val))  # Use 100 validation samples
    X_val_sample = X_val[:n_samples]
    
    # For TreeExplainer, we need feature names
    feature_names = feature_order  # Already have this from Phase 2
    
    # Run SHAP analysis
    shap_success = analyze_shap(
        model=best_model,
        X_train_sample=X_train[:100],  # Sample of training data for explainer
        X_val_sample=X_val_sample,
        feature_names=feature_names,
        class_names=class_names,
        model_name=best_model_name
    )
    
    if shap_success:
        print("\n✅ SHAP analysis saved as PNG files")
        
        # Save SHAP values for later use
        try:
            # Create SHAP values for entire validation set
            if 'XGBoost' in best_model_name or 'Random Forest' in best_model_name:
                explainer = shap.TreeExplainer(best_model)
                shap_values = explainer.shap_values(X_val)
                
                # Save SHAP values
                import joblib
                joblib.dump(shap_values, 'models/shap_values.pkl')
                joblib.dump(explainer.expected_value, 'models/shap_expected.pkl')
                print("✅ SHAP values saved to 'models/shap_values.pkl'")
        except:
            pass
else:
    print("\n⚠️ SHAP not available - skipping feature importance analysis")

# -------------------------------------------------------------------
# 8. OVERFITTING CHECK
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" OVERFITTING CHECK")
print("=" * 80)

# Predict on training
y_train_pred = best_model.predict(X_train)
train_acc = accuracy_score(y_train_enc, y_train_pred)
val_acc = results_df.iloc[0]['Accuracy']

print(f"Training Accuracy: {train_acc:.4f}")
print(f"Validation Accuracy: {val_acc:.4f}")
print(f"Difference: {train_acc - val_acc:.4f}")

if train_acc - val_acc > 0.1:
    print("⚠️ WARNING: Model may be overfitting!")
else:
    print("✅ No significant overfitting detected")

# -------------------------------------------------------------------
# 9. CONFUSION MATRIX VISUALIZATION
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" GENERATING VISUALIZATIONS")
print("=" * 80)

fig, axes = plt.subplots(2, 3, figsize=(18, 12))
fig.suptitle(f'Model Performance Analysis - Best Model: {best_model_name}', fontsize=16)

# 1. F1 Macro Comparison
ax = axes[0, 0]
ax.barh(results_df['Model'], results_df['F1_Macro'], color='steelblue')
ax.set_xlabel('F1 Macro Score')
ax.set_title('Model Comparison (F1 Macro)')
ax.set_xlim(0.5, 1.0)

# 2. Training Time
ax = axes[0, 1]
ax.barh(results_df['Model'], results_df['Time_sec'], color='coral')
ax.set_xlabel('Time (seconds)')
ax.set_title('Training Time Comparison')
ax.set_xscale('log')

# 3. Per-Class F1 for Top 3
ax = axes[0, 2]
top3 = results_df.head(3)
x = np.arange(len(class_names))
width = 0.25
colors = ['blue', 'orange', 'green']
for i, (_, row) in enumerate(top3.iterrows()):
    f1_vals = [row[f'F1_{c}'] for c in class_names]
    ax.bar(x + i*width, f1_vals, width, label=row['Model'], color=colors[i], alpha=0.7)
ax.set_xticks(x + width)
ax.set_xticklabels(class_names, rotation=45)
ax.set_ylabel('F1 Score')
ax.set_title('Per-Class F1 (Top 3 Models)')
ax.legend()
ax.set_ylim(0, 1)

# 4. Confusion Matrix - Best Model
ax = axes[1, 0]
cm = confusion_matrix(y_val_enc, best_pred)
sns.heatmap(cm, annot=True, fmt='d', ax=ax,
            xticklabels=class_names, yticklabels=class_names,
            cmap='Blues', cbar=False)
ax.set_title(f'Confusion Matrix - {best_model_name}')
ax.set_xlabel('Predicted')
ax.set_ylabel('Actual')

# 5. Classification Report Heatmap
ax = axes[1, 1]
report = classification_report(y_val_enc, best_pred, 
                               target_names=class_names, 
                               output_dict=True)
report_df = pd.DataFrame(report).iloc[:-1, :3]  # Remove support row, keep precision/recall/f1
sns.heatmap(report_df, annot=True, fmt='.3f', ax=ax, cmap='YlOrRd', cbar=False)
ax.set_title('Classification Report - Best Model')

# 6. Class Distribution Comparison
ax = axes[1, 2]
train_counts = [np.sum(y_train_enc == i) for i in range(len(class_names))]
val_counts = [np.sum(y_val_enc == i) for i in range(len(class_names))]
x = np.arange(len(class_names))
width = 0.35
ax.bar(x - width/2, train_counts, width, label='Training', color='steelblue')
ax.bar(x + width/2, val_counts, width, label='Validation', color='coral')
ax.set_xlabel('Class')
ax.set_ylabel('Count')
ax.set_title('Class Distribution: Train vs Validation')
ax.set_xticks(x)
ax.set_xticklabels(class_names, rotation=45)
ax.legend()

plt.tight_layout()
plt.savefig('phase3_detailed_results.png', dpi=150, bbox_inches='tight')
plt.show()
print("✅ Visualizations saved to 'phase3_detailed_results.png'")

# -------------------------------------------------------------------
# 10. TEST SET EVALUATION (KDDTest+)
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" TEST SET EVALUATION (KDDTest+ with Novel Attacks)")
print("=" * 80)

try:
    # Load original test data
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
    ]
    
    test_raw = pd.read_csv('../dataset_artifacts/KDDTest+.txt', names=columns)
    train_raw = pd.read_csv('../dataset_artifacts/KDDTrain+.txt', names=columns)
    
    # Attack mapping (same as Phase 1)
    attack_mapping = {
        'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
        'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
        'processtable': 'DoS', 'udpstorm': 'DoS', 'worm': 'DoS',
        'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
        'mscan': 'Probe', 'saint': 'Probe',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
        'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
        'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
        'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
        'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
        'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L'
    }
    
    test_raw['category'] = test_raw['label'].map(attack_mapping).fillna('Normal')
    
    print(f"\nTest set samples: {len(test_raw):,}")
    print("\nTest set distribution:")
    print(test_raw['category'].value_counts())
    
    # Apply preprocessing
    print("\nApplying preprocessing to test set...")
    
    # Encode categoricals
    for col in encoders:
        oe = encoders[col]
        test_raw[col] = test_raw[col].astype(str).apply(
            lambda x: oe.transform([[x]])[0][0] if x in oe.categories_[0] else -1
        ).astype(int)
    
    # Scale numericals
    num_cols = [c for c in feature_order if c not in encoders.keys()]
    test_raw[num_cols] = scaler.transform(test_raw[num_cols])
    
    # Prepare feature matrix
    X_test = test_raw[feature_order].values
    y_test = test_raw['category'].values
    y_test_enc = le.transform(y_test)
    
    print("✅ Test set preprocessed")
    
    # Evaluate best model on test set
    print(f"\n Evaluating {best_model_name} on test set...")
    y_test_pred = best_model.predict(X_test)
    
    test_acc = accuracy_score(y_test_enc, y_test_pred)
    test_f1_macro = f1_score(y_test_enc, y_test_pred, average='macro')
    test_f1_per_class = f1_score(y_test_enc, y_test_pred, average=None)
    
    print(f"\nTest Set Results:")
    print(f"  Accuracy: {test_acc:.4f}")
    print(f"  F1 Macro: {test_f1_macro:.4f}")
    print("\nPer-class F1:")
    for i, cls in enumerate(class_names):
        print(f"  {cls}: {test_f1_per_class[i]:.4f}")
    
    # Detailed classification report
    print("\nDetailed Classification Report:")
    print(classification_report(y_test_enc, y_test_pred, target_names=class_names))
    
    # Identify novel attacks performance
    train_attacks = set()
    for label in train_raw['label'].unique():
        if label != 'normal':
            train_attacks.add(label)
    
    test_attacks = set()
    for label in test_raw['label'].unique():
        if label != 'normal':
            test_attacks.add(label)
    
    novel_attacks = test_attacks - train_attacks
    print(f"\n Novel Attack Types in Test Set: {len(novel_attacks)}")
    
    for attack in list(novel_attacks)[:10]:  # Show first 10
        attack_indices = test_raw[test_raw['label'] == attack].index
        if len(attack_indices) > 0:
            attack_pred = y_test_pred[attack_indices]
            attack_true = y_test_enc[attack_indices]
            attack_acc = np.mean(attack_pred == attack_true)
            print(f"  {attack}: {attack_acc:.2%} accuracy ({len(attack_indices)} samples)")
    
    # Save test results
    test_results = {
        'accuracy': test_acc,
        'f1_macro': test_f1_macro,
        'per_class_f1': {cls: test_f1_per_class[i] for i, cls in enumerate(class_names)}
    }
    with open('test_set_results.json', 'w') as f:
        json.dump(test_results, f, indent=2)
    print("\n✅ Test results saved to 'test_set_results.json'")
    
except Exception as e:
    print(f"⚠️ Could not evaluate on test set: {e}")

# -------------------------------------------------------------------
# 11. CALCULATE MODEL WEIGHTS FOR ENSEMBLE
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print(" CALCULATING MODEL WEIGHTS FOR ENSEMBLE")
print("=" * 80)

total_accuracy = sum(model_accuracies.values())
model_weights = {name.lower().replace(' ', '_'): acc/total_accuracy 
                 for name, acc in model_accuracies.items()}

joblib.dump(model_weights, 'models/model_weights.pkl')
print("✅ Model weights saved to 'models/model_weights.pkl'")

print("\nModel Weights:")
for name, weight in sorted(model_weights.items(), key=lambda x: x[1], reverse=True):
    print(f"  {name}: {weight:.3f}")

# -------------------------------------------------------------------
# 12. SAVE SCALER AND FEATURE INFO
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("💾 SAVING PREPROCESSORS FOR DEPLOYMENT")
print("=" * 80)

# Save scaler (already fitted)
joblib.dump(scaler, 'models/scaler.pkl')
print("✅ Scaler saved to 'models/scaler.pkl'")

# Save feature order
joblib.dump(feature_order, 'models/feature_order.pkl')
print("✅ Feature order saved to 'models/feature_order.pkl'")

# -------------------------------------------------------------------
# 13. PCAP ANALYSIS MODULE (from original code)
# -------------------------------------------------------------------
if scapy_available:
    print("\n" + "=" * 80)
    print("🔌 LOADING PCAP ANALYSIS MODULE")
    print("=" * 80)
    
    class NetworkTrafficAnalyzer:
        def __init__(self, trained_model, scaler, feature_columns, class_names, encoders):
            self.model = trained_model
            self.scaler = scaler
            self.feature_columns = feature_columns
            self.class_names = class_names
            self.encoders = encoders
            
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
            print(f"\n📁 Analyzing PCAP file: {pcap_file}")
            
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
                    # Add derived features
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
                    
                print(f"✅ Successfully extracted features from {total_analyzed} packets")
                return df
                
            except Exception as e:
                print(f"❌ Error reading PCAP file: {str(e)}")
                return pd.DataFrame()
        
        def get_risk_level(self, malicious_percentage):
            """Determine risk level based on malicious percentage"""
            if malicious_percentage > 10:
                return "🔴 HIGH RISK"
            elif malicious_percentage > 5:
                return "🟠 MEDIUM RISK"
            elif malicious_percentage > 1:
                return "🟡 LOW RISK"
            else:
                return "🟢 CLEAN"
        
        def get_recommendation(self, malicious_percentage):
            """Get recommendation based on risk level"""
            if malicious_percentage > 10:
                return "Immediate investigation required!"
            elif malicious_percentage > 5:
                return "Further monitoring recommended."
            elif malicious_percentage > 1:
                return "Minor suspicious activity detected."
            else:
                return "No significant threats detected."
        
        def analyze_pcap(self, pcap_file, confidence_threshold=0.5):
            """Main analysis function for PCAP files"""
            print("\n" + "="*80)
            print("🔍 NETWORK TRAFFIC ANALYSIS REPORT")
            print("="*80)
            
            pcap_df = self.pcap_to_dataframe(pcap_file)
            
            if pcap_df.empty:
                print("❌ No valid network packets found in the file.")
                return None
            
            # Ensure all required columns exist
            missing_cols = set(self.feature_columns) - set(pcap_df.columns)
            for col in missing_cols:
                pcap_df[col] = 0
            
            pcap_df = pcap_df[self.feature_columns]
            
            # Scale features
            X_pcap_scaled = self.scaler.transform(pcap_df)
            
            # Get predictions and probabilities
            try:
                if hasattr(self.model, "predict_proba"):
                    probabilities = self.model.predict_proba(X_pcap_scaled)
                    predictions = np.argmax(probabilities, axis=1)
                    confidence_scores = np.max(probabilities, axis=1)
                else:
                    predictions = self.model.predict(X_pcap_scaled)
                    confidence_scores = np.ones(len(predictions))  # Default confidence
            except:
                predictions = self.model.predict(X_pcap_scaled)
                confidence_scores = np.ones(len(predictions))
            
            # Apply confidence threshold
            high_conf_mask = confidence_scores >= confidence_threshold
            filtered_predictions = predictions[high_conf_mask]
            filtered_confidence = confidence_scores[high_conf_mask]
            
            # Count malicious (any class except Normal)
            malicious_mask = filtered_predictions != 0  # 0 is Normal
            malicious_count = np.sum(malicious_mask)
            total_analyzed = len(filtered_predictions)
            
            malicious_percentage = (malicious_count / total_analyzed * 100) if total_analyzed > 0 else 0
            
            print(f"\n ANALYSIS RESULTS (Threshold: {confidence_threshold}):")
            print(f"   Total packets analyzed: {total_analyzed}")
            print(f"   Malicious packets detected: {malicious_count}")
            print(f"   Malicious traffic percentage: {malicious_percentage:.2f}%")
            
            # Attack type breakdown
            if malicious_count > 0:
                print("\n Attack Type Breakdown:")
                attack_indices = np.where(filtered_predictions != 0)[0]
                attack_types = filtered_predictions[attack_indices]
                for i, cls in enumerate(self.class_names):
                    if i != 0:  # Skip Normal
                        count = np.sum(attack_types == i)
                        if count > 0:
                            pct = (count / malicious_count) * 100
                            print(f"   {cls}: {count} ({pct:.1f}%)")
            
            # Risk assessment
            risk_level = self.get_risk_level(malicious_percentage)
            recommendation = self.get_recommendation(malicious_percentage)
            
            print(f"\n⚠️ RISK ASSESSMENT: {risk_level}")
            print(f"💡 RECOMMENDATION: {recommendation}")
            
            # Generate visualizations
            self.visualize_pcap_analysis(pcap_df, filtered_predictions, filtered_confidence, 
                                         confidence_threshold, risk_level)
            
            # Generate HTML report
            self.generate_html_report(pcap_df, filtered_predictions, filtered_confidence,
                                      malicious_percentage, risk_level, recommendation)
            
            return {
                'total_packets': total_analyzed,
                'malicious_packets': malicious_count,
                'malicious_percentage': malicious_percentage,
                'risk_level': risk_level,
                'recommendation': recommendation,
                'threshold': confidence_threshold
            }
        
        def visualize_pcap_analysis(self, pcap_df, predictions, confidence_scores, threshold, risk_level):
            """Generate visualizations for PCAP analysis"""
            
            fig, axes = plt.subplots(2, 3, figsize=(18, 12))
            fig.suptitle(f'PCAP Analysis Dashboard - Risk Level: {risk_level}', fontsize=16)
            
            # 1. Threat Distribution
            ax = axes[0, 0]
            malicious_count = np.sum(predictions != 0)
            normal_count = len(predictions) - malicious_count
            sizes = [normal_count, malicious_count]
            labels = ['Normal', 'Malicious']
            colors = ['#2ecc71', '#e74c3c']
            ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax.set_title('Threat Distribution')
            
            # 2. Attack Type Distribution
            ax = axes[0, 1]
            if malicious_count > 0:
                attack_indices = np.where(predictions != 0)[0]
                attack_types = predictions[attack_indices]
                attack_counts = [np.sum(attack_types == i) for i in range(1, len(self.class_names))]
                attack_labels = self.class_names[1:]  # Skip Normal
                ax.bar(attack_labels, attack_counts, color=['#e74c3c', '#f39c12', '#9b59b6', '#3498db'])
                ax.set_title('Attack Type Distribution')
                ax.set_ylabel('Count')
            else:
                ax.text(0.5, 0.5, 'No malicious traffic detected', ha='center', va='center')
                ax.set_title('Attack Type Distribution')
            
            # 3. Confidence Score Distribution
            ax = axes[0, 2]
            ax.hist(confidence_scores, bins=20, color='#3498db', alpha=0.7)
            ax.axvline(threshold, color='red', linestyle='--', label=f'Threshold: {threshold}')
            ax.set_xlabel('Confidence Score')
            ax.set_ylabel('Frequency')
            ax.set_title('Confidence Score Distribution')
            ax.legend()
            
            # 4. Top Source IPs
            ax = axes[1, 0]
            if 'src_ip' in pcap_df.columns:
                top_sources = pcap_df['src_ip'].value_counts().head(10)
                ax.barh(range(len(top_sources)), top_sources.values, color='#1abc9c')
                ax.set_yticks(range(len(top_sources)))
                ax.set_yticklabels(top_sources.index)
                ax.set_xlabel('Packet Count')
                ax.set_title('Top 10 Source IPs')
            
            # 5. Destination Ports
            ax = axes[1, 1]
            if 'dst_port' in pcap_df.columns:
                top_ports = pcap_df['dst_port'].value_counts().head(10)
                ax.bar(range(len(top_ports)), top_ports.values, color='#e67e22')
                ax.set_xticks(range(len(top_ports)))
                ax.set_xticklabels(top_ports.index, rotation=45)
                ax.set_xlabel('Port Number')
                ax.set_ylabel('Count')
                ax.set_title('Top 10 Destination Ports')
            
            # 6. Protocol Distribution
            ax = axes[1, 2]
            if 'protocol' in pcap_df.columns:
                protocol_counts = pcap_df['protocol'].value_counts()
                protocol_labels = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
                protocol_names = [protocol_labels.get(p, str(p)) for p in protocol_counts.index]
                ax.pie(protocol_counts.values, labels=protocol_names, autopct='%1.1f%%')
                ax.set_title('Protocol Distribution')
            
            plt.tight_layout()
            
            # Save with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f'pcap_analysis_{timestamp}.png'
            plt.savefig(filename, dpi=150, bbox_inches='tight')
            print(f"📸 PCAP visualizations saved as '{filename}'")
            plt.show()
            plt.close()
        
        def generate_html_report(self, pcap_df, predictions, confidence_scores,
                                 malicious_percentage, risk_level, recommendation):
            """Generate HTML report with visualizations"""
            
            malicious_count = np.sum(predictions != 0)
            total_count = len(predictions)
            
            # Risk color coding
            if "HIGH" in risk_level:
                risk_color = "#e74c3c"
            elif "MEDIUM" in risk_level:
                risk_color = "#f39c12"
            elif "LOW" in risk_level:
                risk_color = "#f1c40f"
            else:
                risk_color = "#2ecc71"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Network Traffic Analysis Report</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; 
                           background-color: #f5f5f5; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                              color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
                    .container {{ max-width: 1200px; margin: 0 auto; }}
                    .metric {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px;
                              box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .risk {{ background: {risk_color}; color: white; padding: 20px; border-radius: 10px;
                            margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                            gap: 20px; margin: 20px 0; }}
                    .card {{ background: white; padding: 20px; border-radius: 10px;
                            box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
                    table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                    th {{ background: #667eea; color: white; padding: 12px; text-align: left; }}
                    td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                    tr:hover {{ background-color: #f5f5f5; }}
                    .timestamp {{ color: #666; font-size: 0.9em; margin-top: 10px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔍 Network Traffic Analysis Report</h1>
                        <p>Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    </div>
                    
                    <div class="grid">
                        <div class="card">
                            <h3>📊 Summary Metrics</h3>
                            <p>Total Packets: <strong>{total_count}</strong></p>
                            <p>Malicious Packets: <strong>{malicious_count}</strong></p>
                            <p>Malicious %: <strong>{malicious_percentage:.2f}%</strong></p>
                        </div>
                        
                        <div class="card">
                            <h3>📈 Detection Statistics</h3>
                            <p>Normal Traffic: <strong>{total_count - malicious_count}</strong></p>
                            <p>Attack Types: <strong>{len(self.class_names)-1}</strong></p>
                            <p>Avg Confidence: <strong>{np.mean(confidence_scores):.3f}</strong></p>
                        </div>
                    </div>
                    
                    <div class="risk">
                        <h2>⚠️ Risk Assessment</h2>
                        <p>Risk Level: <strong>{risk_level}</strong></p>
                        <p>Recommendation: <strong>{recommendation}</strong></p>
                    </div>
                    
                    <div class="metric">
                        <h3>📋 Top Suspicious Packets</h3>
                        {self.generate_top_suspicious_table(pcap_df, predictions, confidence_scores)}
                    </div>
                    
                    <div class="timestamp">
                        <p>Report generated by NSL-KDD IDS System v1.0</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Save HTML report
            filename = 'pcap_analysis_report.html'
            with open(filename, 'w') as f:
                f.write(html_content)
            print(f"📄 HTML report saved as '{filename}'")
        
        def generate_top_suspicious_table(self, pcap_df, predictions, confidence_scores, top_n=10):
            """Generate HTML table of top suspicious packets"""
            malicious_indices = np.where(predictions != 0)[0]
            
            if len(malicious_indices) > 0:
                # Sort by confidence
                malicious_conf = confidence_scores[malicious_indices]
                sorted_idx = malicious_indices[np.argsort(malicious_conf)[::-1]][:top_n]
                
                table_rows = ""
                for idx in sorted_idx:
                    packet_data = pcap_df.iloc[idx] if idx < len(pcap_df) else None
                    if packet_data is not None:
                        src_ip = packet_data.get('src_ip', 'N/A')
                        dst_ip = packet_data.get('dst_ip', 'N/A')
                        dst_port = packet_data.get('dst_port', 'N/A')
                        packet_len = packet_data.get('packet_length', 'N/A')
                        conf = confidence_scores[idx]
                        pred_class = self.class_names[predictions[idx]]
                        
                        table_rows += f"""
                        <tr>
                            <td>{src_ip}</td>
                            <td>{dst_ip}:{dst_port}</td>
                            <td>{pred_class}</td>
                            <td>{packet_len}</td>
                            <td>{conf:.3f}</td>
                        </tr>
                        """
                
                return f"""
                <table>
                    <tr>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Attack Type</th>
                        <th>Size (bytes)</th>
                        <th>Confidence</th>
                    </tr>
                    {table_rows}
                </table>
                """
            return "<p>No suspicious packets detected.</p>"
    
    # Initialize analyzer with best model
    analyzer = NetworkTrafficAnalyzer(
        trained_model=best_model,
        scaler=scaler,
        feature_columns=feature_order,
        class_names=class_names,
        encoders=encoders
    )
    
    print("✅ PCAP Analyzer initialized successfully")
    
    # Ask user if they want to analyze a PCAP file
    print("\n" + "=" * 80)
    user_choice = input("\n🔍 Do you want to analyze a PCAP file? (yes/no): ").strip().lower()
    
    if user_choice in ['yes', 'y']:
        pcap_path = input("Enter the path to your PCAP file: ").strip().strip('"\'')
        
        if not os.path.exists(pcap_path):
            print(f"❌ File not found: {pcap_path}")
        elif not pcap_path.lower().endswith(('.pcap', '.pcapng', '.cap')):
            print("❌ Please provide a valid PCAP file (.pcap, .pcapng, .cap)")
        else:
            # Test with multiple thresholds
            print("\n" + "=" * 80)
            print(" TESTING MULTIPLE CONFIDENCE THRESHOLDS")
            print("=" * 80)
            
            thresholds = [0.5, 0.7, 0.8, 0.9]
            results_list = []
            
            for threshold in thresholds:
                print(f"\n--- Testing with threshold {threshold} ---")
                result = analyzer.analyze_pcap(pcap_path, confidence_threshold=threshold)
                if result:
                    results_list.append(result)
            
            # Summary
            print("\n" + "=" * 80)
            print(" THRESHOLD ANALYSIS SUMMARY")
            print("=" * 80)
            for result in results_list:
                print(f"Threshold {result['threshold']}: {result['malicious_percentage']:.1f}% malicious → {result['risk_level']}")
            
            # Final recommendation
            best_result = results_list[-1]  # Highest threshold
            print(f"\n✅ FINAL RECOMMENDATION (based on threshold {best_result['threshold']}):")
            print(f"   Risk Level: {best_result['risk_level']}")
            print(f"   {best_result['recommendation']}")
    
    else:
        print("\n✅ Training completed. You can analyze PCAP files later by running the analyzer module.")

else:
    print("\n⚠️ Scapy not installed - PCAP analysis disabled.")
    print("   To enable PCAP analysis, install scapy: pip install scapy")

# -------------------------------------------------------------------
# 14. FINAL SUMMARY
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("📋 PHASE 3 COMPLETE - FINAL SUMMARY")
print("=" * 80)

print(f"""
✅ TRAINING COMPLETED SUCCESSFULLY!

📊 BEST MODEL: {best_model_name}
   • F1 Macro: {results_df.iloc[0]['F1_Macro']:.4f}
   • Accuracy: {results_df.iloc[0]['Accuracy']:.4f}
   • U2R F1: {results_df.iloc[0]['F1_U2R']:.4f}
   • R2L F1: {results_df.iloc[0]['F1_R2L']:.4f}

📁 FILES GENERATED:
   • models/ - All trained models ({len(models)} models)
   • models/scaler.pkl - StandardScaler for deployment
   • models/feature_order.pkl - Feature names in correct order
   • models/class_names.pkl - Class labels (5 classes)
   • models/model_weights.pkl - Accuracy-based weights for ensemble
   • models/best_model_info.pkl - Best model metadata
   • phase3_results.csv - Model comparison results
   • phase3_detailed_results.png - Performance visualizations
   • test_set_results.json - Performance on KDDTest+ (with novel attacks)
   • pcap_analysis_report.html - PCAP analysis report (if analyzed)

🔧 NEXT STEPS:
   1. Use saved models in production: joblib.load('models/best_model.pkl')
   2. For ensemble predictions: load all models and use model_weights.pkl
   3. To analyze new traffic: run the PCAP analyzer again
   4. For cross-validation: use raw arrays + Pipeline with SMOTENC inside folds

{"✅ PCAP analysis performed" if scapy_available and 'user_choice' in locals() and user_choice in ['yes','y'] else "⏸️ PCAP analysis skipped - run later with analyzer"}
""")

print("=" * 80)
print("MODEL TRAINING DONE SUCCESSFULLY!")
print("=" * 80)
