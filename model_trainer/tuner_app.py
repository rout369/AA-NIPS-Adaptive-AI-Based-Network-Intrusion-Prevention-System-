from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import json
import os
import zipfile
import io
import threading
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, regularizers

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables for training status
training_active = False
current_loss_history = []
model = None
scaler = None
feature_names = None
X_train = None
X_val = None

# ============================================
# DATA LOADING FUNCTION
# ============================================
def load_and_prepare_data():
    global scaler, feature_names, X_train, X_val
    
    print("📂 Loading dataset...")
    
    # Try to find dataset
    dataset_path = '../dataset/Monday-WorkingHours_trimmed_100k.csv'
    if not os.path.exists(dataset_path):
        # Try current directory
        if os.path.exists('Monday-WorkingHours_trimmed_100k.csv'):
            dataset_path = 'Monday-WorkingHours_trimmed_100k.csv'
        else:
            # Look for any csv file
            csv_files = [f for f in os.listdir('../dataset') if f.endswith('.csv')] if os.path.exists('../dataset') else []
            csv_files += [f for f in os.listdir('.') if f.endswith('.csv')]
            if csv_files:
                dataset_path = csv_files[0]
                print(f"✅ Found: {dataset_path}")
            else:
                raise Exception("No CSV file found!")
    
    # Load data
    df = pd.read_csv(dataset_path, nrows=50000)  # Use 50k for faster testing
    
    # Clean column names
    df.columns = df.columns.str.strip().str.replace(' ', '_').str.replace('/', '_')
    
    # Keep only numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    df = df[numeric_cols]
    
    # Remove infinities and NaN
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
    # Select features
    desired_features = [
        'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets',
        'Total_Backward_Packets', 'Fwd_Packet_Length_Mean', 'Flow_Bytes_s',
        'Flow_Packets_s', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
    ]
    
    available_features = []
    for col in desired_features:
        if col in df.columns:
            available_features.append(col)
    
    feature_names = available_features
    X = df[available_features].values
    
    # Normalize
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Split
    X_train, X_val = train_test_split(X_scaled, test_size=0.2, random_state=42)
    
    print(f"✅ Data loaded: {len(X_train)} training samples, {len(X_val)} validation samples")
    return True

# Load data at startup
try:
    load_and_prepare_data()
    print("✅ Data loaded successfully!")
except Exception as e:
    print(f"⚠️ Could not load data: {e}")

# ============================================
# MODEL BUILDING FUNCTION
# ============================================
def build_model(config):
    input_dim = X_train.shape[1] if X_train is not None else 9
    
    input_layer = layers.Input(shape=(input_dim,))
    x = input_layer
    
    # Encoder
    x = layers.Dense(
        config['architecture']['layer1'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU()(x)
    x = layers.Dropout(config['regularization']['dropout'])(x)
    
    x = layers.Dense(
        config['architecture']['layer2'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU()(x)
    x = layers.Dropout(config['regularization']['dropout'])(x)
    
    # Bottleneck
    x = layers.Dense(
        config['architecture']['bottleneck'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU()(x)
    
    # Decoder
    x = layers.Dense(
        config['architecture']['layer2'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU()(x)
    x = layers.Dropout(config['regularization']['dropout'])(x)
    
    x = layers.Dense(
        config['architecture']['layer1'],
        kernel_regularizer=regularizers.l2(config['regularization']['l2'])
    )(x)
    if config['regularization']['use_batchnorm']:
        x = layers.BatchNormalization()(x)
    x = layers.LeakyReLU()(x)
    x = layers.Dropout(config['regularization']['dropout'])(x)
    
    # Output
    output = layers.Dense(input_dim, activation='linear')(x)
    
    model = Model(input_layer, output)
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=config['training']['learning_rate']),
        loss='mse'
    )
    
    return model

# ============================================
# ROUTES
# ============================================
@app.route('/')
def index():
    return render_template('tuner.html')

@app.route('/test_config', methods=['POST'])
def test_config():
    global X_train, X_val
    
    if X_train is None:
        return jsonify({'error': 'Data not loaded'}), 500
    
    config = request.json
    print(f"🔬 Testing config: {config}")
    
    try:
        # Build model with config
        model = build_model(config)
        
        # Train for 1 epoch
        history = model.fit(
            X_train, X_train,
            epochs=1,
            batch_size=config['training']['batch_size'],
            validation_data=(X_val, X_val),
            verbose=0
        )
        
        return jsonify({
            'loss': float(history.history['loss'][0]),
            'val_loss': float(history.history['val_loss'][0])
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/start_training', methods=['POST'])
def start_training():
    global training_active, current_loss_history, X_train, X_val, model, scaler, feature_names
    
    if X_train is None:
        return jsonify({'error': 'Data not loaded'}), 500
    
    config = request.json
    training_active = True
    current_loss_history = []
    
    def train_thread():
        global training_active, current_loss_history, model, scaler, feature_names
        
        try:
            # Build model
            model = build_model(config)
            
            # Custom callback for live updates
            class LiveUpdateCallback(keras.callbacks.Callback):
                def on_epoch_end(self, epoch, logs=None):
                    current_loss_history.append(logs['loss'])
                    socketio.emit('loss_update', {
                        'loss': logs['loss'],
                        'val_loss': logs['val_loss'],
                        'epoch': epoch,
                        'loss_history': current_loss_history
                    })
            
            start_time = time.time()
            history = model.fit(
                X_train, X_train,
                epochs=config['training']['epochs'],
                batch_size=config['training']['batch_size'],
                validation_data=(X_val, X_val),
                callbacks=[LiveUpdateCallback()],
                verbose=0
            )
            train_time = time.time() - start_time
            
            # Calculate thresholds
            X_val_pred = model.predict(X_val, verbose=0)
            mse = np.mean(np.square(X_val - X_val_pred), axis=1)
            
            threshold = float(np.percentile(mse, config['threshold']['percentile']))
            strict_threshold = float(np.percentile(mse, 99))
            
            # Save model
            os.makedirs('models', exist_ok=True)
            model.save('models/autoencoder.h5')
            joblib.dump(scaler, 'models/autoencoder_scaler.pkl')
            joblib.dump(feature_names, 'models/autoencoder_features.pkl')
            joblib.dump({
                'threshold': threshold,
                'strict_threshold': strict_threshold
            }, 'models/autoencoder_threshold.pkl')
            
            socketio.emit('training_complete', {
                'message': 'Training complete!',
                'time': train_time,
                'threshold': threshold,
                'strict': strict_threshold
            })
            
        except Exception as e:
            socketio.emit('training_error', {'error': str(e)})
        finally:
            training_active = False
    
    thread = threading.Thread(target=train_thread)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started'})

@app.route('/export_model', methods=['POST'])
def export_model():
    # Create zip file with all model files
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        if os.path.exists('models/autoencoder.h5'):
            zf.write('models/autoencoder.h5', 'autoencoder.h5')
            zf.write('models/autoencoder_scaler.pkl', 'autoencoder_scaler.pkl')
            zf.write('models/autoencoder_features.pkl', 'autoencoder_features.pkl')
            zf.write('models/autoencoder_threshold.pkl', 'autoencoder_threshold.pkl')
    
    memory_file.seek(0)
    return send_file(
        memory_file,
        download_name='autoencoder_model.zip',
        as_attachment=True,
        mimetype='application/zip'
    )

@app.route('/status')
def status():
    return jsonify({
        'training_active': training_active,
        'data_loaded': X_train is not None,
        'samples': len(X_train) if X_train is not None else 0
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Autoencoder Hyperparameter Tuner")
    print("="*60)
    print("📊 Starting server...")
    print("🌐 Open http://localhost:5001 in your browser")
    print("="*60)
    socketio.run(app, debug=True, port=5001)