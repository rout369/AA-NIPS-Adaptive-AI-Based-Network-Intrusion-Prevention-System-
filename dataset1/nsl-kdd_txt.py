import pandas as pd
import numpy as np

# For KDDTrain+.txt and KDDTest+.txt files
def convert_nslkdd_to_csv(input_file, output_csv):
    # NSL-KDD column names (based on KDD Cup 1999)
    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files',
        'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
        'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
        'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
        'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
        'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
    ]
    
    # Load the data
    df = pd.read_csv(input_file, header=None, names=column_names)
    
    # Map attack types to binary labels (0=normal, 1=attack)
    # For multi-class, you can keep attack_type as is
    attacks = ['normal']
    df['label'] = df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Save to CSV
    df.to_csv(output_csv, index=False)
    print(f"Converted {input_file} to {output_csv}")
    print(f"Shape: {df.shape}")
    print(f"Label distribution:\n{df['label'].value_counts()}")

# Usage
convert_nslkdd_to_csv('KDDTrain+.txt', 'nsl_kdd_train.csv')
convert_nslkdd_to_csv('KDDTest+.txt', 'nsl_kdd_test.csv')