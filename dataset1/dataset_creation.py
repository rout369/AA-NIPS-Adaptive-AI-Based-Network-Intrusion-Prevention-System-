# ============================================
# PHASE 2 (FINAL): CREATE BALANCED TRAINING DATA
# Using SMOTENC – correct categorical handling
# Fully dynamic, guarded, and CV‑ready
# ============================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.model_selection import StratifiedShuffleSplit
from imblearn.over_sampling import SMOTENC
import warnings
import joblib
import json
import os
warnings.filterwarnings('ignore')

print("=" * 80)
print("PHASE 2 (FINAL): CREATING BALANCED DATASET WITH SMOTENC")
print("=" * 80)

# -------------------------------------------------------------------
# 1. Load raw data
# -------------------------------------------------------------------
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

train_raw = pd.read_csv('KDDTrain+.txt', names=columns)
test_raw = pd.read_csv('KDDTest+.txt', names=columns)

# Attack to category mapping
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

train_raw['category'] = train_raw['label'].map(attack_mapping).fillna('Normal')
test_raw['category'] = test_raw['label'].map(attack_mapping).fillna('Normal')

print("\n📊 Original training distribution:")
print(train_raw['category'].value_counts())

# -------------------------------------------------------------------
# 2. Stratified train / validation split (80/20)
# -------------------------------------------------------------------
sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
for train_idx, val_idx in sss.split(train_raw, train_raw['category']):
    train_set = train_raw.iloc[train_idx].copy()
    val_set = train_raw.iloc[val_idx].copy()

print(f"\nTraining samples after split: {len(train_set)}")
print(f"Validation samples: {len(val_set)}")

# -------------------------------------------------------------------
# 3. Define column groups and create binary labels
# -------------------------------------------------------------------
cat_cols = ['protocol_type', 'service', 'flag']
num_cols = [c for c in train_raw.columns if c not in cat_cols + ['label', 'category', 'difficulty']]

# --- NEW: Remove zero‑variance numerical columns ---
zero_var_cols = [col for col in num_cols if train_set[col].std() == 0]
if zero_var_cols:
    print(f"\n⚠️  Removing zero‑variance columns: {zero_var_cols}")
    num_cols = [col for col in num_cols if col not in zero_var_cols]
    train_set.drop(columns=zero_var_cols, inplace=True)
    val_set.drop(columns=zero_var_cols, inplace=True)
# ---------------------------------------------------

train_set['binary_label'] = (train_set['category'] != 'Normal').astype(int)
val_set['binary_label'] = (val_set['category'] != 'Normal').astype(int)

# -------------------------------------------------------------------
# 4. Encode categoricals with OrdinalEncoder (unchanged)
# -------------------------------------------------------------------
encoders = {}
for col in cat_cols:
    oe = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1, dtype=np.int32)
    oe.fit(train_set[[col]].astype(str))
    train_set[col] = oe.transform(train_set[[col]].astype(str)).astype(int)
    val_set[col] = oe.transform(val_set[[col]].astype(str)).astype(int)
    encoders[col] = oe

print("\nCategoricals encoded with OrdinalEncoder (unseen -> -1).")

# -------------------------------------------------------------------
# 5. Scale numerical features (fit on train only)
# -------------------------------------------------------------------
scaler = StandardScaler()
train_set[num_cols] = scaler.fit_transform(train_set[num_cols])
val_set[num_cols] = scaler.transform(val_set[num_cols])
print("Numerical features scaled.")

# -------------------------------------------------------------------
# 6. Zero‑variance check after scaling (should now pass)
# -------------------------------------------------------------------
X_train_raw_check = train_set[num_cols + cat_cols].values
if np.any(np.std(X_train_raw_check[:, :len(num_cols)], axis=0) == 0):
    # This should no longer happen, but keep as safety
    raise ValueError("Some numerical features still have zero variance after removal – check manually.")
else:
    print("Zero‑variance check passed.")

# -------------------------------------------------------------------
# 7. Define dynamic sampling strategy with guardrails
# -------------------------------------------------------------------
orig_counts = Counter(train_set['category'])
k_neighbors = 3

print("\nOriginal class counts (training):")
for k, v in sorted(orig_counts.items()):
    print(f"  {k}: {v}")

# Rare-class minimum check
for cls in ['U2R', 'R2L']:
    if orig_counts.get(cls, 0) <= k_neighbors:
        raise ValueError(f"CRITICAL: Too few samples for {cls} ({orig_counts.get(cls, 0)}) to perform SMOTE with k_neighbors={k_neighbors}.")

# Dynamic targets with safe caps
sampling_strategy = {}
if orig_counts.get('R2L', 0) < 3000:
    sampling_strategy['R2L'] = int(min(orig_counts['R2L'] * 3, 10000))
if orig_counts.get('U2R', 0) < 500:
    sampling_strategy['U2R'] = int(min(orig_counts['U2R'] * 5, 2000))

print("\nDynamic SMOTENC target strategy:")
for cls, target in sampling_strategy.items():
    print(f"  {cls}: {orig_counts[cls]} → {target}")

# -------------------------------------------------------------------
# 8. Apply SMOTENC
# -------------------------------------------------------------------
feature_order = num_cols + cat_cols
X_train_raw = train_set[feature_order].values
y_train_raw = train_set['category'].values

cat_indices = list(range(len(num_cols), len(num_cols) + len(cat_cols)))

smote_nc = SMOTENC(
    categorical_features=cat_indices,
    sampling_strategy=sampling_strategy,
    random_state=42,
    k_neighbors=k_neighbors
)

print("\nGenerating synthetic samples with SMOTENC...")
X_train_bal, y_train_bal = smote_nc.fit_resample(X_train_raw, y_train_raw)
print("SMOTENC completed.")

balanced_counts = Counter(y_train_bal)
print("\n📊 Balanced training distribution:")
for cls in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']:
    print(f"  {cls}: {balanced_counts.get(cls,0)}")

# -------------------------------------------------------------------
# VISUALIZATION 1: Class distribution before vs after SMOTENC
# -------------------------------------------------------------------
fig, axes = plt.subplots(1, 3, figsize=(18, 5))
fig.suptitle('NSL-KDD: Before vs After SMOTENC Balancing', fontsize=14, fontweight='bold')

# Before SMOTENC
ax1 = axes[0]
categories = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
original_counts = [orig_counts.get(c, 0) for c in categories]
colors_before = ['steelblue', 'steelblue', 'steelblue', 'coral', 'red']
bars1 = ax1.bar(categories, original_counts, color=colors_before)
ax1.set_title('Before SMOTENC (Training Set)')
ax1.set_ylabel('Number of Samples')
ax1.set_yscale('log')  # log scale to see tiny U2R
for bar, count in zip(bars1, original_counts):
    ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
             f'{count:,}', ha='center', va='bottom', fontsize=9)

# After SMOTENC
ax2 = axes[1]
balanced_counts_list = [balanced_counts.get(c, 0) for c in categories]
colors_after = ['steelblue', 'steelblue', 'steelblue', 'lightgreen', 'lightgreen']
bars2 = ax2.bar(categories, balanced_counts_list, color=colors_after)
ax2.set_title('After SMOTENC (Balanced)')
ax2.set_ylabel('Number of Samples')
for bar, count in zip(bars2, balanced_counts_list):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
             f'{count:,}', ha='center', va='bottom', fontsize=9)

# Rare classes comparison
ax3 = axes[2]
rare_cats = ['R2L', 'U2R']
rare_before = [orig_counts.get('R2L', 0), orig_counts.get('U2R', 0)]
rare_after = [balanced_counts.get('R2L', 0), balanced_counts.get('U2R', 0)]

x = np.arange(len(rare_cats))
width = 0.35
bars_before = ax3.bar(x - width/2, rare_before, width, label='Before SMOTENC', color='coral')
bars_after = ax3.bar(x + width/2, rare_after, width, label='After SMOTENC', color='lightgreen')
ax3.set_xlabel('Category')
ax3.set_ylabel('Number of Samples')
ax3.set_title('Rare Classes: Before vs After')
ax3.set_xticks(x)
ax3.set_xticklabels(rare_cats)
ax3.legend()
for bars in [bars_before, bars_after]:
    for bar in bars:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height):,}', ha='center', va='bottom', fontsize=10)

plt.tight_layout()
plt.savefig('dataset_artifacts/smotenc_distribution_comparison.png', dpi=150)
plt.show()
print("\n✅ Distribution comparison plot saved to 'dataset_artifacts/smotenc_distribution_comparison.png'")

# -------------------------------------------------------------------
# 9. SYNTHETIC SAMPLE QUALITY VERIFICATION
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("🔍 SYNTHETIC SAMPLE QUALITY VERIFICATION")
print("=" * 80)

X_train_bal_df = pd.DataFrame(X_train_bal, columns=feature_order)

# Drift thresholds
DRIFT_THRESHOLD_MEAN = 40
DRIFT_THRESHOLD_STD = 50

drift_df = None  # initialize
max_mean_drift = None
max_std_drift = None

# Check U2R (most critical minority class)
u2r_before = train_set[train_set['category'] == 'U2R'][num_cols]
u2r_after = X_train_bal_df[y_train_bal == 'U2R'][num_cols]

if len(u2r_before) > 0 and len(u2r_after) > 0:
    drift_df = pd.DataFrame({
        'Before_Mean': u2r_before.mean(),
        'After_Mean': u2r_after.mean(),
        'Before_Std': u2r_before.std(),
        'After_Std': u2r_after.std()
    })
    drift_df['Mean_Drift_%'] = ((drift_df['After_Mean'] - drift_df['Before_Mean']) /
                                 (drift_df['Before_Mean'].abs() + 1e-9)) * 100
    drift_df['Std_Drift_%'] = ((drift_df['After_Std'] - drift_df['Before_Std']) /
                                (drift_df['Before_Std'] + 1e-9)) * 100

    max_mean_drift = drift_df['Mean_Drift_%'].abs().max()
    max_std_drift = drift_df['Std_Drift_%'].abs().max()

    print("\n📊 Feature drift for U2R class (top 10 features by mean drift):")
    display_cols = ['Before_Mean', 'After_Mean', 'Mean_Drift_%', 'Before_Std', 'After_Std', 'Std_Drift_%']
    print(drift_df[display_cols].round(4).sort_values('Mean_Drift_%', key=abs, ascending=False).head(10).to_string())

    if max_mean_drift > DRIFT_THRESHOLD_MEAN:
        print(f"\n⚠️  WARNING: Some features show >{DRIFT_THRESHOLD_MEAN}% mean drift – oversampling may be too aggressive.")
    else:
        print(f"\n✅ Mean drift within acceptable range (<{DRIFT_THRESHOLD_MEAN}%).")

    if max_std_drift > DRIFT_THRESHOLD_STD:
        print(f"⚠️  Some features show >{DRIFT_THRESHOLD_STD}% standard deviation drift – synthetic samples may have unrealistic variance.")
    else:
        print(f"✅ Standard deviation drift within acceptable range (<{DRIFT_THRESHOLD_STD}%).")
else:
    print("U2R class not present in training – skipping drift check.")

# -------------------------------------------------------------------
# VISUALIZATION 2: U2R feature drift (top features by mean drift)
# -------------------------------------------------------------------
if drift_df is not None:
    # Sort by absolute mean drift, take top 15
    plot_df = drift_df.reindex(drift_df['Mean_Drift_%'].abs().sort_values(ascending=False).index).head(15)

    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(plot_df))
    colors = ['red' if x > DRIFT_THRESHOLD_MEAN else 'orange' if x > 20 else 'green'
              for x in plot_df['Mean_Drift_%'].abs()]
    ax.barh(y_pos, plot_df['Mean_Drift_%'], color=colors)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(plot_df.index)
    ax.axvline(x=DRIFT_THRESHOLD_MEAN, color='black', linestyle='--', label=f'Threshold {DRIFT_THRESHOLD_MEAN}%')
    ax.axvline(x=-DRIFT_THRESHOLD_MEAN, color='black', linestyle='--')
    ax.set_xlabel('Mean Drift (%)')
    ax.set_title('U2R Feature Drift (After SMOTENC)')
    ax.legend()
    plt.tight_layout()
    plt.savefig('dataset_artifacts/u2r_drift_plot.png', dpi=150)
    plt.show()
    print("✅ U2R drift plot saved to 'dataset_artifacts/u2r_drift_plot.png'")
else:
    print("⚠️  No U2R samples – skipping drift plot.")

# -------------------------------------------------------------------
# 10. Save preprocessors, metadata, and arrays (with CV warning)
# -------------------------------------------------------------------

os.makedirs('dataset_artifacts', exist_ok=True)

joblib.dump(scaler, 'dataset_artifacts/scaler.pkl')
joblib.dump(encoders, 'dataset_artifacts/encoders.pkl')
joblib.dump(feature_order, 'dataset_artifacts/feature_order.pkl')

X_val_raw = val_set[feature_order].values
y_val_raw = val_set['category'].values
y_val_binary = val_set['binary_label'].values

# Build metadata dictionary (may contain NumPy types)
metadata = {
    "random_state": 42,
    "test_size": 0.2,
    "sampling_strategy": {k: int(v) for k, v in sampling_strategy.items()},
    "k_neighbors": k_neighbors,
    "categorical_columns": cat_cols,
    "numerical_columns": num_cols,
    "original_train_counts": dict(orig_counts),
    "balanced_counts": dict(balanced_counts),
    "drift_threshold_mean": DRIFT_THRESHOLD_MEAN,
    "drift_threshold_std": DRIFT_THRESHOLD_STD,
    "max_mean_drift": max_mean_drift,
    "max_std_drift": max_std_drift,
    "drift_check_passed": (max_mean_drift is not None and max_mean_drift <= DRIFT_THRESHOLD_MEAN) if max_mean_drift is not None else None
}

# ---- CONVERSION FUNCTION ----
def convert_to_serializable(obj):
    """Recursively convert NumPy types to native Python types."""
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, (np.bool_)):
        return bool(obj)
    elif isinstance(obj, (np.ndarray,)):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    else:
        return obj
# -----------------------------

# Convert metadata to JSON‑serializable form
metadata_serializable = convert_to_serializable(metadata)

# Save metadata as JSON
with open('dataset_artifacts/dataset_metadata.json', 'w') as f:
    json.dump(metadata_serializable, f, indent=2)

# Save numpy arrays
np.save('dataset_artifacts/X_train_raw.npy', X_train_raw)
np.save('dataset_artifacts/y_train_raw.npy', y_train_raw)
np.save('dataset_artifacts/y_train_binary.npy', train_set['binary_label'].values)
np.save('dataset_artifacts/X_train_bal.npy', X_train_bal)
np.save('dataset_artifacts/y_train_bal.npy', y_train_bal)
np.save('dataset_artifacts/X_val_raw.npy', X_val_raw)
np.save('dataset_artifacts/y_val_raw.npy', y_val_raw)
np.save('dataset_artifacts/y_val_binary.npy', y_val_binary)

print("\n✅ All artifacts saved in 'dataset_artifacts/' folder.")

# -------------------------------------------------------------------
# 11. CV warning
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("⚠️  CRITICAL NOTE FOR PHASE 3:")
print("    The saved balanced arrays (X_train_bal, y_train_bal) are for FINAL model training only.")
print("    For cross‑validation or hyperparameter tuning, DO NOT use these arrays directly.")
print("    Instead, build a Pipeline with SMOTENC inside each fold.")
print("=" * 80)

# -------------------------------------------------------------------
# VISUALIZATION 3: Simple bar chart of final class counts
# -------------------------------------------------------------------
plt.figure(figsize=(10, 5))
plt.bar(balanced_counts.keys(), balanced_counts.values(), color='steelblue')
plt.title('Final Balanced Class Distribution')
plt.xlabel('Class')
plt.ylabel('Number of Samples')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('dataset_artifacts/final_balanced_distribution.png', dpi=150)
plt.show()

# -------------------------------------------------------------------
# 12. FINAL SUMMARY REPORT (like the original)
# -------------------------------------------------------------------
print("\n" + "=" * 80)
print("📋 PHASE 2 COMPLETE - SUMMARY REPORT")
print("=" * 80)

total_original = len(y_train_raw)
total_balanced = len(y_train_bal)
new_synthetic = total_balanced - total_original

print(f"""
BALANCING SUMMARY:
─────────────────────────────────────────────────────
Original training data: {total_original:,} samples
Balanced training data: {total_balanced:,} samples
New synthetic samples: {new_synthetic:,}

CLASS DISTRIBUTION COMPARISON:
─────────────────────────────────────────────────────
Class     Original     Balanced    Change
Normal    {orig_counts.get('Normal',0):6,} → {balanced_counts.get('Normal',0):6,}    {balanced_counts.get('Normal',0) - orig_counts.get('Normal',0):+6,}
DoS       {orig_counts.get('DoS',0):6,} → {balanced_counts.get('DoS',0):6,}    {balanced_counts.get('DoS',0) - orig_counts.get('DoS',0):+6,}
Probe     {orig_counts.get('Probe',0):6,} → {balanced_counts.get('Probe',0):6,}    {balanced_counts.get('Probe',0) - orig_counts.get('Probe',0):+6,}
R2L       {orig_counts.get('R2L',0):6,} → {balanced_counts.get('R2L',0):6,}    {balanced_counts.get('R2L',0) - orig_counts.get('R2L',0):+6,}
U2R       {orig_counts.get('U2R',0):6,} → {balanced_counts.get('U2R',0):6,}    {balanced_counts.get('U2R',0) - orig_counts.get('U2R',0):+6,}

SYNTHETIC QUALITY CHECK (U2R class):
─────────────────────────────────────────────────────
""")

if max_mean_drift is not None:
    print(f"Maximum mean drift: {max_mean_drift:.2f}% (threshold {DRIFT_THRESHOLD_MEAN}%)")
    print(f"Maximum std drift: {max_std_drift:.2f}% (threshold {DRIFT_THRESHOLD_STD}%)")
    status = '✓ PASS' if max_mean_drift <= DRIFT_THRESHOLD_MEAN else '⚠️ WARNING'
    print(f"Status: {status}")
else:
    print("U2R class absent – no drift check performed.")

print(f"""
KEY ACHIEVEMENTS:
─────────────────────────────────────────────────────
✓ U2R increased from {orig_counts.get('U2R',0)} → {balanced_counts.get('U2R',0)} samples
✓ R2L increased from {orig_counts.get('R2L',0)} → {balanced_counts.get('R2L',0)} samples
✓ Majority classes preserved (no data loss)
✓ Validation set remains untouched (real-world imbalanced)
✓ Binary labels created for hierarchical modeling
✓ All data and preprocessors saved

NEXT STEPS:
─────────────────────────────────────────────────────
Phase 3: Train models on balanced data:
├── Use X_train_bal.npy, y_train_bal.npy for final training
├── Use X_val_raw.npy, y_val_raw.npy for validation
├── Apply same preprocessing to test set using saved scaler/encoders
└── For cross‑validation, use raw arrays + Pipeline with SMOTENC
""")

print("\n" + "=" * 80)
print("✅ PHASE 2 COMPLETED SUCCESSFULLY!")
print("=" * 80)
