# ============================================
# NSL-KDD DATA EXPLORATION
# Goal: Understand the dataset completely
# No ML models yet, just exploration!
# ============================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Set style for better visualizations
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

print("=" * 80)
print("NSL-KDD DATASET EXPLORATION")
print("=" * 80)

# ============================================
# STEP 1: LOAD THE DATA
# ============================================

# Column names from NSL-KDD documentation
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

# Load the data
print("\n📂 LOADING DATASETS...")
try:
    train = pd.read_csv('KDDTrain+.txt', names=columns)
    test = pd.read_csv('KDDTest+.txt', names=columns)
    print("✓ Training set loaded successfully")
    print("✓ Test set loaded successfully")
except FileNotFoundError:
    print("❌ Error: Dataset files not found!")
    print("Please download KDDTrain+.txt and KDDTest+.txt")
    print("and place them in the current directory.")
    exit()

# ============================================
# STEP 2: BASIC INFORMATION
# ============================================

print("\n" + "=" * 80)
print("📊 BASIC DATASET INFORMATION")
print("=" * 80)

print(f"\n📁 TRAINING SET:")
print(f"   • Shape: {train.shape[0]:,} rows × {train.shape[1]} columns")
print(f"   • Memory usage: {train.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

print(f"\n📁 TEST SET:")
print(f"   • Shape: {test.shape[0]:,} rows × {test.shape[1]} columns")
print(f"   • Memory usage: {test.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

# Check for missing values
print("\n🔍 CHECKING FOR MISSING VALUES:")
print(f"   • Training set missing values: {train.isnull().sum().sum()}")
print(f"   • Test set missing values: {test.isnull().sum().sum()}")

# ============================================
# STEP 3: FEATURE TYPES
# ============================================

print("\n" + "=" * 80)
print("🔧 FEATURE TYPES")
print("=" * 80)

# Identify categorical and numerical columns
categorical_cols = ['protocol_type', 'service', 'flag']
numerical_cols = [col for col in columns if col not in categorical_cols + ['label', 'difficulty']]

print(f"\n📊 CATEGORICAL FEATURES ({len(categorical_cols)}):")
for col in categorical_cols:
    unique_count = train[col].nunique()
    print(f"   • {col}: {unique_count} unique values")
    if unique_count < 20:  # Show values for small categoricals
        print(f"     Values: {sorted(train[col].unique())}")

print(f"\n📈 NUMERICAL FEATURES ({len(numerical_cols)}):")
print("   First 5 numerical features:")
for col in numerical_cols[:5]:
    print(f"   • {col}: range [{train[col].min():.2f}, {train[col].max():.2f}]")

# ============================================
# STEP 4: UNDERSTAND THE LABELS
# ============================================

print("\n" + "=" * 80)
print("🏷️ LABEL ANALYSIS")
print("=" * 80)

# Get all unique attack types
train_attacks = set(train['label'].unique())
test_attacks = set(test['label'].unique())
all_attacks = train_attacks.union(test_attacks)

print(f"\n📋 ATTACK TYPES:")
print(f"   • Training set: {len(train_attacks)} unique attack types")
print(f"   • Test set: {len(test_attacks)} unique attack types")
print(f"   • Total: {len(all_attacks)} unique attack types across both sets")

print("\n📋 ATTACK TYPES IN TRAINING SET:")
attack_list = sorted(train_attacks - {'normal'})
for i, attack in enumerate(attack_list):
    print(f"   {i+1:2d}. {attack}")
    if i == 20:  # Show first 20
        remaining = len(attack_list) - 21
        if remaining > 0:
            print(f"      ... and {remaining} more")
            break

print("\n📋 ATTACK TYPES IN TEST SET (NOVEL ONES MARKED):")
novel_attacks = test_attacks - train_attacks - {'normal'}
known_attacks = test_attacks.intersection(train_attacks) - {'normal'}

print(f"\n   ✓ KNOWN ATTACKS ({len(known_attacks)}):")
for attack in sorted(known_attacks)[:10]:
    print(f"      • {attack}")
if len(known_attacks) > 10:
    print(f"      ... and {len(known_attacks)-10} more")

print(f"\n   ✗ NOVEL ATTACKS (in test but NOT in training) ({len(novel_attacks)}):")
for attack in sorted(novel_attacks):
    print(f"      • {attack} ⭐")

# ============================================
# STEP 5: MAP TO 5 CATEGORIES
# ============================================

print("\n" + "=" * 80)
print("🗺️ MAPPING TO 5 ATTACK CATEGORIES")
print("=" * 80)

# Complete attack mapping
attack_mapping = {
    # DoS attacks
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
    'processtable': 'DoS', 'udpstorm': 'DoS', 'worm': 'DoS',
    
    # Probe attacks
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    
    # U2R attacks
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
    
    # R2L attacks
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'httptunnel': 'R2L'
}

# Apply mapping
train['category'] = train['label'].map(attack_mapping).fillna('Normal')
test['category'] = test['label'].map(attack_mapping).fillna('Normal')

# ============================================
# STEP 6: CLASS DISTRIBUTION ANALYSIS
# ============================================

print("\n" + "=" * 80)
print("📊 CLASS DISTRIBUTION ANALYSIS")
print("=" * 80)

# Training set distribution
train_dist = train['category'].value_counts()
train_percent = train['category'].value_counts(normalize=True) * 100

print("\n📊 TRAINING SET DISTRIBUTION:")
print("-" * 60)
for category in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']:
    count = train_dist.get(category, 0)
    percent = train_percent.get(category, 0)
    bar = '█' * int(percent / 2)  # Visual bar
    print(f"   {category:8} : {count:7,} ({percent:5.2f}%) {bar}")

# Test set distribution
test_dist = test['category'].value_counts()
test_percent = test['category'].value_counts(normalize=True) * 100

print("\n📊 TEST SET DISTRIBUTION:")
print("-" * 60)
for category in ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']:
    count = test_dist.get(category, 0)
    percent = test_percent.get(category, 0)
    bar = '█' * int(percent / 2)
    print(f"   {category:8} : {count:7,} ({percent:5.2f}%) {bar}")

# ============================================
# STEP 7: VISUALIZE THE IMBALANCE
# ============================================

print("\n" + "=" * 80)
print("📈 CREATING VISUALIZATIONS...")
print("=" * 80)

# Create figure with subplots
fig, axes = plt.subplots(2, 2, figsize=(15, 12))
fig.suptitle('NSL-KDD Dataset Analysis', fontsize=16, fontweight='bold')

# 1. Class distribution comparison
ax1 = axes[0, 0]
categories = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
train_counts = [train_dist.get(c, 0) for c in categories]
test_counts = [test_dist.get(c, 0) for c in categories]

x = np.arange(len(categories))
width = 0.35

bars1 = ax1.bar(x - width/2, train_counts, width, label='Training', color='steelblue')
bars2 = ax1.bar(x + width/2, test_counts, width, label='Test', color='coral')

ax1.set_xlabel('Category')
ax1.set_ylabel('Number of Samples')
ax1.set_title('Class Distribution: Training vs Test')
ax1.set_xticks(x)
ax1.set_xticklabels(categories)
ax1.legend()
ax1.set_yscale('log')  # Log scale to see tiny classes

# Add value labels on bars
for bars in [bars1, bars2]:
    for bar in bars:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom', fontsize=8)

# 2. Training set pie chart
ax2 = axes[0, 1]
colors = ['lightgreen', 'lightcoral', 'gold', 'lightskyblue', 'lightpink']
explode = (0, 0, 0, 0.1, 0.2)  # Explode rare classes
ax2.pie(train_counts, labels=categories, autopct='%1.1f%%',
        startangle=90, colors=colors, explode=explode)
ax2.set_title('Training Set Class Distribution')

# 3. Test set pie chart
ax3 = axes[1, 0]
ax3.pie(test_counts, labels=categories, autopct='%1.1f%%',
        startangle=90, colors=colors, explode=explode)
ax3.set_title('Test Set Class Distribution')

# 4. Rare classes zoom
ax4 = axes[1, 1]
rare_categories = ['R2L', 'U2R']
rare_train = [train_dist.get('R2L', 0), train_dist.get('U2R', 0)]
rare_test = [test_dist.get('R2L', 0), test_dist.get('U2R', 0)]

x_rare = np.arange(len(rare_categories))
bars_rare1 = ax4.bar(x_rare - width/2, rare_train, width, label='Training', color='steelblue')
bars_rare2 = ax4.bar(x_rare + width/2, rare_test, width, label='Test', color='coral')

ax4.set_xlabel('Category')
ax4.set_ylabel('Number of Samples')
ax4.set_title('Rare Classes: R2L and U2R')
ax4.set_xticks(x_rare)
ax4.set_xticklabels(rare_categories)
ax4.legend()

# Add value labels
for bars in [bars_rare1, bars_rare2]:
    for bar in bars:
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height):,}', ha='center', va='bottom', fontsize=10)

plt.tight_layout()
plt.savefig('nsl_kdd_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

print("\n✓ Visualizations saved as 'nsl_kdd_analysis.png'")

# ============================================
# STEP 8: NOVEL ATTACKS DETAILED ANALYSIS
# ============================================

print("\n" + "=" * 80)
print("🔍 DETAILED NOVEL ATTACKS ANALYSIS")
print("=" * 80)

# Get novel attacks per category
novel_by_category = {}
for attack in novel_attacks:
    category = attack_mapping.get(attack, 'Unknown')
    if category not in novel_by_category:
        novel_by_category[category] = []
    novel_by_category[category].append(attack)

print("\n📋 NOVEL ATTACKS BY CATEGORY:")
for category in ['U2R', 'R2L', 'Probe', 'DoS']:
    if category in novel_by_category:
        print(f"\n   {category}:")
        for attack in novel_by_category[category]:
            count_in_test = len(test[test['label'] == attack])
            print(f"      • {attack}: {count_in_test} samples in test set")

# ============================================
# STEP 9: FEATURE DISTRIBUTIONS BY CLASS
# ============================================

print("\n" + "=" * 80)
print("📊 FEATURE DISTRIBUTION BY CLASS")
print("=" * 80)

# Select important features to examine
important_features = ['src_bytes', 'dst_bytes', 'count', 'duration']
print("\nAnalyzing feature distributions for different classes...")

fig, axes = plt.subplots(2, 2, figsize=(15, 10))
fig.suptitle('Feature Distributions by Class', fontsize=14)

for idx, feature in enumerate(important_features):
    row, col = idx // 2, idx % 2
    ax = axes[row, col]
    
    # Sample data for visualization (take subset for clarity)
    for category in ['Normal', 'DoS', 'U2R']:
        subset = train[train['category'] == category][feature]
        # Clip to 99th percentile for better visualization
        if len(subset) > 0:
            subset = subset.clip(upper=subset.quantile(0.99))
            ax.hist(subset, bins=50, alpha=0.5, label=category, density=True)
    
    ax.set_xlabel(feature)
    ax.set_ylabel('Density')
    ax.set_title(f'{feature} Distribution by Class')
    ax.legend()
    ax.set_xscale('symlog')  # Log scale for skewed features

plt.tight_layout()
plt.savefig('feature_distributions.png', dpi=300, bbox_inches='tight')
plt.show()

# ============================================
# STEP 10: SUMMARY REPORT
# ============================================

print("\n" + "=" * 80)
print("📋 EXPLORATION SUMMARY REPORT")
print("=" * 80)

print(f"""
DATASET SUMMARY:
─────────────────────────────────────────────────────
Training samples: {train.shape[0]:,}
Test samples: {test.shape[0]:,}
Features: {len(numerical_cols)} numerical, {len(categorical_cols)} categorical
Missing values: None

CLASS DISTRIBUTION (TRAINING):
─────────────────────────────────────────────────────
Normal: {train_dist.get('Normal', 0):,} ({train_percent.get('Normal', 0):.2f}%)
DoS:    {train_dist.get('DoS', 0):,} ({train_percent.get('DoS', 0):.2f}%)
Probe:  {train_dist.get('Probe', 0):,} ({train_percent.get('Probe', 0):.2f}%)
R2L:    {train_dist.get('R2L', 0):,} ({train_percent.get('R2L', 0):.2f}%)
U2R:    {train_dist.get('U2R', 0):,} ({train_percent.get('U2R', 0):.4f}%) ← EXTREMELY RARE!

CLASS DISTRIBUTION (TEST):
─────────────────────────────────────────────────────
Normal: {test_dist.get('Normal', 0):,} ({test_percent.get('Normal', 0):.2f}%)
DoS:    {test_dist.get('DoS', 0):,} ({test_percent.get('DoS', 0):.2f}%)
Probe:  {test_dist.get('Probe', 0):,} ({test_percent.get('Probe', 0):.2f}%)
R2L:    {test_dist.get('R2L', 0):,} ({test_percent.get('R2L', 0):.2f}%) ← MORE THAN TRAINING!
U2R:    {test_dist.get('U2R', 0):,} ({test_percent.get('U2R', 0):.4f}%) ← MORE THAN TRAINING!

NOVEL ATTACKS (in test but NOT in training):
─────────────────────────────────────────────────────
U2R: {', '.join(novel_by_category.get('U2R', []))}
R2L: {', '.join(novel_by_category.get('R2L', []))}
Probe: {', '.join(novel_by_category.get('Probe', []))}
DoS: {', '.join(novel_by_category.get('DoS', []))}

KEY CHALLENGES IDENTIFIED:
─────────────────────────────────────────────────────
1. Extreme class imbalance (U2R has only {train_dist.get('U2R', 0)} samples)
2. Novel attack types in test set ({len(novel_attacks)} new attacks)
3. R2L and U2R are very rare but critically important
4. Test distribution differs from training distribution
""")

print("\n" + "=" * 80)
print("DATA EXPLORATION COMPLETE!")
print("=" * 80)
