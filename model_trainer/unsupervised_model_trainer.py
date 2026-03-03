#!/usr/bin/env python3
"""
Enhanced Autoencoder Training for Zero-Day Detection
Includes: Deeper Architecture, Regularization, Dynamic Threshold,
Convolutional Layers, Attention Mechanism, and Hyperparameter Tuning
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import os
import time
import json
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, regularizers

print("="*60)
print("AUTOENCODER TRAINING - ALL FEATURES")
print("="*60)
print(f"TensorFlow version: {tf.__version__}")
print(f"Keras version: {keras.__version__}")

# ============================================
# HYPERPARAMETER CONFIGURATION
# ============================================
# You can modify these values to tune the model
CONFIG = {
    # Deeper Architecture Settings
    'architecture': {
        'layer1_size': 32,      # First hidden layer
        'layer2_size': 16,      # Second hidden layer
        'bottleneck_size': 8,   # Compressed representation
        'num_layers': 3,        # Number of layers in encoder/decoder
        'use_conv': True,       # Use convolutional layers
        'use_attention': True,  # Use attention mechanism
    },
    
    # Regularization Settings
    'regularization': {
        'l2_lambda': 0.001,     # L2 regularization strength
        'dropout_rate': 0.2,     # Dropout probability
        'use_batchnorm': True,   # Use batch normalization
    },
    
    # Dynamic Threshold Settings
    'threshold': {
        'sigma_multiplier': 3.0,  # For statistical threshold (mean + sigma*std)
        'percentile': 95,          # For percentile-based threshold
        'use_dynamic': True,       # Use dynamic thresholding
    },
    
    # Convolutional Settings
    'convolutional': {
        'filters': 32,            # Number of filters
        'kernel_size': 3,          # Kernel size for conv layers
        'pool_size': 2,            # Pooling size
    },
    
    # Attention Settings
    'attention': {
        'heads': 4,                # Number of attention heads
        'key_dim': 16,             # Key dimension for attention
        'use_self_attention': True, # Use self-attention
    },
    
    # Training Settings
    'training': {
        'learning_rate': 0.001,
        'batch_size': 256,
        'epochs': 30,
        'validation_split': 0.2,
        'early_stop_patience': 5,
        'reduce_lr_patience': 3,
    },
    
    # Data Settings
    'data': {
        'dataset_path': '../dataset/Monday-WorkingHours_trimmed_100k.csv',
        'max_samples': 100000,     # Maximum samples to use
        'test_size': 0.2,
        'random_state': 42,
    }
}

# ============================================
# DATA LOADING AND PREPARATION
# ============================================
print("\n📂 Loading dataset...")
start_time = time.time()

if not os.path.exists(CONFIG['data']['dataset_path']):
    # Try to find any trimmed file
    csv_files = [f for f in os.listdir('../dataset') if f.endswith('.csv')]
    if csv_files:
        CONFIG['data']['dataset_path'] = f"../dataset/{csv_files[0]}"
        print(f"✅ Found: {CONFIG['data']['dataset_path']}")
    else:
        raise Exception("No CSV file found in ../dataset/")

# Load data
df = pd.read_csv(CONFIG['data']['dataset_path'], nrows=CONFIG['data']['max_samples'])
print(f"✅ Loaded {len(df)} rows in {time.time()-start_time:.1f} seconds")

# Clean column names
df.columns = df.columns.str.strip().str.replace(' ', '_').str.replace('/', '_')

# Keep only numeric columns
numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
df = df[numeric_cols]

# Remove infinities and NaN
df = df.replace([np.inf, -np.inf], np.nan).dropna()

print(f"   After cleaning: {len(df)} samples with {len(numeric_cols)} features")

# Filter for BENIGN traffic only
if 'Label' in df.columns:
    df_benign = df[df['Label'] == 'BENIGN'].copy()
    print(f"   BENIGN samples: {len(df_benign)}")
    if len(df_benign) > 0:
        df = df_benign.drop(columns=['Label'])
    else:
        print("   No BENIGN found, using all data")
else:
    print("   No Label column, assuming all BENIGN")

# ============================================
# FEATURE SELECTION
# ============================================
print("\n🔍 Selecting features...")

# Features that match your firewall
desired_features = [
    'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets',
    'Total_Backward_Packets', 'Fwd_Packet_Length_Mean', 'Flow_Bytes_s',
    'Flow_Packets_s', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
]

# Keep only features that exist
available_features = []
for col in desired_features:
    if col in df.columns:
        available_features.append(col)

print(f"   Using {len(available_features)} features: {available_features}")

X = df[available_features].values
feature_names = available_features

# ============================================
# NORMALIZE FEATURES
# ============================================
print("\n📊 Normalizing features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split into train/validation
X_train, X_val = train_test_split(
    X_scaled, 
    test_size=CONFIG['data']['test_size'], 
    random_state=CONFIG['data']['random_state']
)

print(f"   Training: {len(X_train)} samples")
print(f"   Validation: {len(X_val)} samples")
print(f"   Features: {X_train.shape[1]}")

# ============================================
# BUILD ENHANCED AUTOENCODER
# ============================================
print("\n🏗️ Building enhanced autoencoder...")

input_dim = X_train.shape[1]

def build_autoencoder(config):
    """Build autoencoder with all features"""
    
    input_layer = layers.Input(shape=(input_dim,))
    x = input_layer
    
    # ========================================
    # 1. CONVOLUTIONAL LAYERS (if enabled)
    # ========================================
    if config['architecture']['use_conv']:
        # Reshape for 1D convolution
        x = layers.Reshape((input_dim, 1))(x)
        
        # Encoder convolutional layers
        x = layers.Conv1D(
            filters=config['convolutional']['filters'],
            kernel_size=config['convolutional']['kernel_size'],
            padding='same',
            activation='relu',
            kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
        )(x)
        x = layers.MaxPooling1D(pool_size=config['convolutional']['pool_size'])(x)
        
        x = layers.Conv1D(
            filters=config['convolutional']['filters'] // 2,
            kernel_size=config['convolutional']['kernel_size'],
            padding='same',
            activation='relu',
            kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
        )(x)
        x = layers.MaxPooling1D(pool_size=config['convolutional']['pool_size'])(x)
        
        # Flatten for dense layers
        x = layers.Flatten()(x)
        
        # Calculate flattened dimension
        conv_output_dim = x.shape[1]
    
    # ========================================
    # 2. ENCODER DENSE LAYERS
    # ========================================
    # Layer 1
    x = layers.Dense(
        config['architecture']['layer1_size'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
    )(x if not config['architecture']['use_conv'] else x)
    
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU(alpha=0.1)(x)
    if config['regularization']['dropout_rate'] > 0:
        x = layers.Dropout(config['regularization']['dropout_rate'])(x)
    
    # Layer 2
    x = layers.Dense(
        config['architecture']['layer2_size'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU(alpha=0.1)(x)
    if config['regularization']['dropout_rate'] > 0:
        x = layers.Dropout(config['regularization']['dropout_rate'])(x)
    
    # ========================================
    # 3. BOTTLENECK WITH ATTENTION
    # ========================================
    bottleneck = layers.Dense(
        config['architecture']['bottleneck_size'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda']),
        name='bottleneck'
    )(x)
    
    if config['architecture']['use_attention'] and config['attention']['use_self_attention']:
        # Add self-attention at bottleneck
        bottleneck_reshaped = layers.Reshape((1, config['architecture']['bottleneck_size']))(bottleneck)
        attention = layers.MultiHeadAttention(
            num_heads=config['attention']['heads'],
            key_dim=config['attention']['key_dim']
        )(bottleneck_reshaped, bottleneck_reshaped)
        attention = layers.Flatten()(attention)
        # Skip connection
        bottleneck = layers.Add()([bottleneck, attention])
    
    if config['regularization']['use_batchnorm']:
        bottleneck = layers.BatchNormalization()(bottleneck)
    bottleneck = layers.LeakyReLU(alpha=0.1)(bottleneck)
    
    # ========================================
    # 4. DECODER (mirror encoder)
    # ========================================
    x = bottleneck
    
    # Layer 2 (decoder)
    x = layers.Dense(
        config['architecture']['layer2_size'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU(alpha=0.1)(x)
    if config['regularization']['dropout_rate'] > 0:
        x = layers.Dropout(config['regularization']['dropout_rate'])(x)
    
    # Layer 1 (decoder)
    x = layers.Dense(
        config['architecture']['layer1_size'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU(alpha=0.1)(x)
    if config['regularization']['dropout_rate'] > 0:
        x = layers.Dropout(config['regularization']['dropout_rate'])(x)
    
    # ========================================
    # 5. OUTPUT LAYER
    # ========================================
    if config['architecture']['use_conv']:
        # Reshape back for convolutional decoder
        x = layers.Dense(conv_output_dim)(x)
        x = layers.Reshape((-1, 1))(x)
        
        # Decoder convolutional layers
        x = layers.UpSampling1D(size=config['convolutional']['pool_size'])(x)
        x = layers.Conv1D(
            filters=config['convolutional']['filters'] // 2,
            kernel_size=config['convolutional']['kernel_size'],
            padding='same',
            activation='relu',
            kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
        )(x)
        
        x = layers.UpSampling1D(size=config['convolutional']['pool_size'])(x)
        x = layers.Conv1D(
            filters=config['convolutional']['filters'],
            kernel_size=config['convolutional']['kernel_size'],
            padding='same',
            activation='relu',
            kernel_regularizer=regularizers.l2(config['regularization']['l2_lambda'])
        )(x)
        
        x = layers.Flatten()(x)
    
    output_layer = layers.Dense(input_dim, activation='linear')(x)
    
    model = Model(input_layer, output_layer)
    return model

# Build the model
autoencoder = build_autoencoder(CONFIG)

# Compile with Adam optimizer
optimizer = keras.optimizers.Adam(learning_rate=CONFIG['training']['learning_rate'])
autoencoder.compile(optimizer=optimizer, loss='mse')

print(f"\n   Total parameters: {autoencoder.count_params():,}")
autoencoder.summary()

# ============================================
# TRAINING CALLBACKS
# ============================================
callbacks = []

# Early stopping
if CONFIG['training']['early_stop_patience'] > 0:
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss',
        patience=CONFIG['training']['early_stop_patience'],
        restore_best_weights=True,
        verbose=1
    )
    callbacks.append(early_stop)

# Reduce learning rate on plateau
if CONFIG['training']['reduce_lr_patience'] > 0:
    reduce_lr = keras.callbacks.ReduceLROnPlateau(
        monitor='val_loss',
        factor=0.5,
        patience=CONFIG['training']['reduce_lr_patience'],
        min_lr=0.00001,
        verbose=1
    )
    callbacks.append(reduce_lr)

# Custom callback to track training
class TrainingLogger(keras.callbacks.Callback):
    def on_epoch_end(self, epoch, logs=None):
        if epoch % 5 == 0:
            print(f"   Epoch {epoch}: loss = {logs['loss']:.4f}, val_loss = {logs['val_loss']:.4f}")

callbacks.append(TrainingLogger())

# ============================================
# TRAIN THE MODEL
# ============================================
print("\n🔄 Training enhanced autoencoder...")
start_train = time.time()

history = autoencoder.fit(
    X_train, X_train,
    epochs=CONFIG['training']['epochs'],
    batch_size=CONFIG['training']['batch_size'],
    validation_data=(X_val, X_val),
    callbacks=callbacks,
    verbose=0,
    shuffle=True
)

train_time = time.time() - start_train
print(f"\n⏱️ Training completed in {train_time:.1f} seconds")

# ============================================
# CALCULATE DYNAMIC THRESHOLDS
# ============================================
print("\n📈 Calculating dynamic thresholds...")

# Get reconstruction error on validation set
X_val_pred = autoencoder.predict(X_val, verbose=0)
mse = np.mean(np.square(X_val - X_val_pred), axis=1)

# Method 1: Statistical threshold (mean + sigma * std)
mean_error = np.mean(mse)
std_error = np.std(mse)
sigma_threshold = mean_error + CONFIG['threshold']['sigma_multiplier'] * std_error

# Method 2: Percentile threshold
percentile_threshold = np.percentile(mse, CONFIG['threshold']['percentile'])

# Method 3: Combined threshold (use the stricter one)
final_threshold = min(sigma_threshold, percentile_threshold)
strict_threshold = np.percentile(mse, 99)  # 99% threshold

print(f"\n   Threshold Analysis:")
print(f"   Mean error: {mean_error:.4f}")
print(f"   Std error: {std_error:.4f}")
print(f"   Sigma threshold (mean + {CONFIG['threshold']['sigma_multiplier']}σ): {sigma_threshold:.4f}")
print(f"   Percentile threshold ({CONFIG['threshold']['percentile']}%): {percentile_threshold:.4f}")
print(f"   Final threshold: {final_threshold:.4f}")
print(f"   Strict threshold (99%): {strict_threshold:.4f}")

# ============================================
# SAVE MODEL AND ARTIFACTS
# ============================================
print("\n💾 Saving model and artifacts...")

os.makedirs('models', exist_ok=True)

# Save model
autoencoder.save('models/autoencoder.keras')
print(f"   ✅ Autoencoder saved to models/autoencoder.autoencoder.keras")

# Save scaler
joblib.dump(scaler, 'models/autoencoder_scaler.pkl')
print(f"   ✅ Scaler saved to models/autoencoder_scaler.pkl")

# Save feature names
joblib.dump(feature_names, 'models/autoencoder_features.pkl')
print(f"   ✅ Feature names saved to models/autoencoder_features.pkl")

# Save thresholds
thresholds = {
    'threshold': float(final_threshold),
    'strict_threshold': float(strict_threshold),
    'sigma_threshold': float(sigma_threshold),
    'percentile_threshold': float(percentile_threshold),
    'mean_error': float(mean_error),
    'std_error': float(std_error)
}
joblib.dump(thresholds, 'models/autoencoder_threshold.pkl')
print(f"   ✅ Thresholds saved to models/autoencoder_threshold.pkl")

# Save configuration
with open('models/autoencoder_config.json', 'w') as f:
    json.dump(CONFIG, f, indent=2)
print(f"   ✅ Configuration saved to models/autoencoder_config.json")

# ============================================
# VISUALIZATION
# ============================================
print("\n📊 Generating visualizations...")

fig, axes = plt.subplots(2, 3, figsize=(15, 10))

# Plot 1: Training History
axes[0, 0].plot(history.history['loss'], label='Training', linewidth=2)
axes[0, 0].plot(history.history['val_loss'], label='Validation', linewidth=2)
axes[0, 0].set_xlabel('Epoch')
axes[0, 0].set_ylabel('Loss (MSE)')
axes[0, 0].set_title('Training History')
axes[0, 0].legend()
axes[0, 0].grid(True, alpha=0.3)

# Plot 2: Error Distribution
axes[0, 1].hist(mse, bins=50, alpha=0.7, color='blue', edgecolor='black')
axes[0, 1].axvline(final_threshold, color='red', linestyle='--', linewidth=2,
                   label=f'Final: {final_threshold:.4f}')
axes[0, 1].axvline(strict_threshold, color='orange', linestyle='--', linewidth=2,
                   label=f'Strict: {strict_threshold:.4f}')
axes[0, 1].set_xlabel('Reconstruction Error')
axes[0, 1].set_ylabel('Frequency')
axes[0, 1].set_title('Error Distribution')
axes[0, 1].legend()
axes[0, 1].grid(True, alpha=0.3)

# Plot 3: Error by Sample
axes[0, 2].scatter(range(len(mse)), mse, alpha=0.3, s=1, c='blue')
axes[0, 2].axhline(final_threshold, color='red', linestyle='--', label='Threshold')
axes[0, 2].set_xlabel('Sample Index')
axes[0, 2].set_ylabel('Reconstruction Error')
axes[0, 2].set_title('Errors by Sample')
axes[0, 2].legend()
axes[0, 2].grid(True, alpha=0.3)

# Plot 4: Box Plot
axes[1, 0].boxplot(mse)
axes[1, 0].axhline(final_threshold, color='red', linestyle='--', label='Threshold')
axes[1, 0].set_ylabel('Reconstruction Error')
axes[1, 0].set_title('Error Distribution (Box Plot)')
axes[1, 0].legend()
axes[1, 0].grid(True, alpha=0.3)

# Plot 5: Learning Rate over time (if available)
if hasattr(autoencoder.optimizer, 'learning_rate'):
    lr = float(autoencoder.optimizer.learning_rate.numpy())
    axes[1, 1].bar(['Learning Rate'], [lr])
    axes[1, 1].set_ylabel('Value')
    axes[1, 1].set_title(f'Final Learning Rate: {lr:.6f}')
    axes[1, 1].grid(True, alpha=0.3)

# Plot 6: Configuration Summary
config_text = f"Architecture: {CONFIG['architecture']['layer1_size']}-{CONFIG['architecture']['layer2_size']}-{CONFIG['architecture']['bottleneck_size']}\n"
config_text += f"Regularization: L2={CONFIG['regularization']['l2_lambda']}, Dropout={CONFIG['regularization']['dropout_rate']}\n"
config_text += f"Conv: {CONFIG['architecture']['use_conv']}, Attention: {CONFIG['architecture']['use_attention']}\n"
config_text += f"Threshold: {final_threshold:.4f} (strict: {strict_threshold:.4f})"
axes[1, 2].text(0.1, 0.5, config_text, fontsize=10, verticalalignment='center')
axes[1, 2].axis('off')
axes[1, 2].set_title('Configuration')

plt.suptitle('Enhanced Autoencoder Training Results', fontsize=16, fontweight='bold')
plt.tight_layout()
plt.savefig('enhanced_autoencoder_results.png', dpi=150, bbox_inches='tight')
plt.show()
print("   ✅ Visualization saved to enhanced_autoencoder_results.png")

# ============================================
# FINAL SUMMARY
# ============================================
print("\n" + "="*60)
print("✅ ENHANCED AUTOENCODER TRAINING COMPLETE!")
print("="*60)
print(f"\n📊 Final Performance:")
print(f"   Final validation loss: {history.history['val_loss'][-1]:.4f}")
print(f"   Best validation loss: {min(history.history['val_loss']):.4f}")
print(f"   Training time: {train_time:.1f} seconds")
print(f"   Detection threshold: {final_threshold:.4f}")
print(f"   Strict threshold: {strict_threshold:.4f}")

print(f"\n📁 Files saved in models/ folder:")
print("   - autoencoder.h5 (the trained model)")
print("   - autoencoder_scaler.pkl (feature normalizer)")
print("   - autoencoder_features.pkl (feature names)")
print("   - autoencoder_threshold.pkl (anomaly thresholds)")
print("   - autoencoder_config.json (configuration used)")
print("\n📈 Visualization saved: enhanced_autoencoder_results.png")

print("\n" + "="*60)
print("🚀 NEXT STEP: Copy these files to your firewall's ml_pipeline/models/ folder")
print("="*60)