import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings('ignore')
from datetime import datetime, timedelta
import random
import os

# ============================================
# GLOBAL PORT MAPPING DEFINITION
# ============================================

PORT_MAPPING = {
    # Common services
    'http': 80, 'http_443': 443, 'http_8001': 8001, 'http_2784': 2784,
    'ftp': 21, 'ftp_data': 20,
    'ssh': 22, 'telnet': 23,
    'smtp': 25, 'pop_3': 110, 'pop_2': 109, 'imap4': 143,
    'domain': 53, 'domain_u': 53,
    'netbios_ssn': 139, 'netbios_ns': 137, 'netbios_dgm': 138,
    'sunrpc': 111, 'ntp_u': 123, 'snmp': 161,
    'irc': 194, 'ldap': 389,
    'https': 443,
    # Less common services
    'finger': 79, 'time': 37, 'whois': 43,
    'mtp': 350, 'sql_net': 1521, 'bgp': 179,
    'exec': 512, 'login': 513, 'shell': 514,
    'printer': 515, 'uucp': 540,
    'klogin': 543, 'kshell': 544,
    'supdup': 95, 'systat': 11,
    'Z39_50': 210, 'courier': 530,
    'ctf': 84, 'discard': 9, 'echo': 7,
    'gopher': 70, 'hostnames': 101,
    'link': 245, 'name': 42,
    'nnsp': 433, 'nntp': 119,
    'pm_dump': 929, 'private': np.nan,  # Private/random ports
    'red_i': np.nan, 'remote_job': 71,
    'rje': 77, 'sql': 118,
    'tftp_u': 69, 'tim_i': np.nan,
    'urh_i': np.nan, 'urp_i': np.nan,
    'uucp_path': 117, 'vmnet': np.nan,
    'X11': 6000, 'aol': 5190,
    'auth': 113, 'csnet_ns': 105,
    'daytime': 13, 'eco_i': np.nan,
    'ecr_i': np.nan, 'efs': 520,
    'harvest': 267, 'iso_tsap': 102,
    'netstat': 15, 'other': np.nan,
    'urp_i': np.nan
}

# ============================================
# PART 1: Convert ARFF to CSV (Basic Format)
# ============================================

def parse_arff_file(file_path):
    """
    Parse ARFF file manually to handle your exact format
    """
    print(f"Parsing {file_path}...")
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Extract column names and types from @attribute lines
    column_names = []
    column_types = {}
    
    data_start = False
    data_lines = []
    
    for line in lines:
        line = line.strip()
        
        # Skip comments
        if line.startswith('%') or not line:
            continue
            
        # Extract column information
        if line.lower().startswith('@attribute'):
            parts = line.split()
            if len(parts) >= 2:
                col_name = parts[1].strip("'")
                column_names.append(col_name)
                # Store type information if needed
                if '{' in line:
                    column_types[col_name] = 'categorical'
                else:
                    column_types[col_name] = 'numeric'
                    
        # Find start of data section
        elif line.lower().startswith('@data'):
            data_start = True
            continue
            
        # Collect data lines
        elif data_start:
            if line:
                data_lines.append(line)
    
    # Parse the data
    parsed_data = []
    for line in data_lines:
        # Split by comma, handling quoted strings
        row = []
        current = ''
        in_quotes = False
        
        for char in line:
            if char == "'" and not in_quotes:
                in_quotes = True
            elif char == "'" and in_quotes:
                in_quotes = False
            elif char == ',' and not in_quotes:
                row.append(current.strip())
                current = ''
            else:
                current += char
                
        if current:
            row.append(current.strip())
        
        # Ensure we have the right number of columns
        if len(row) == len(column_names):
            parsed_data.append(row)
    
    # Create DataFrame
    df = pd.DataFrame(parsed_data, columns=column_names)
    
    # Convert numeric columns
    for col in df.columns:
        if column_types.get(col) == 'numeric' and col != 'class':
            df[col] = pd.to_numeric(df[col], errors='coerce')
    
    print(f"  Loaded {len(df)} rows with {len(df.columns)} columns")
    print(f"  Columns: {list(df.columns)}")
    print(f"  Label distribution: {df['class'].value_counts().to_dict()}")
    
    return df

def convert_arff_to_csv(arff_file, csv_file):
    """
    Convert ARFF file to CSV
    """
    df = parse_arff_file(arff_file)
    
    # Add binary label (0 = normal, 1 = anomaly/attack)
    df['label'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Also create attack categories if needed
    attack_mapping = {
        'normal': 'normal',
        'anomaly': 'attack'  # In KDDTest-21, it's just 'anomaly'
    }
    df['attack_category'] = df['class'].map(attack_mapping)
    
    # Save to CSV
    df.to_csv(csv_file, index=False)
    print(f"✓ Saved to {csv_file}")
    print(f"  Binary labels: Normal={sum(df['label']==0)}, Attack={sum(df['label']==1)}")
    print("-" * 60)
    
    return df

# ============================================
# PART 2: Create Network Traffic Format
# ============================================

def create_network_traffic_format(df, output_csv, sample_name="nslkdd"):
    """
    Convert NSL-KDD features to your desired network traffic format
    with synthetic IPs, ports, and timestamps
    """
    print(f"Creating network traffic format for {sample_name}...")
    
    n_samples = len(df)
    
    # Create synthetic but realistic network data
    synthetic = pd.DataFrame()
    
    # 1. Generate timestamps (spread over 24 hours)
    base_date = datetime(2025, 4, 7, 0, 0, 0)
    if sample_name == "train":
        base_date = datetime(2025, 4, 6, 0, 0, 0)
    
    time_intervals = np.linspace(0, 86400, n_samples)  # 24 hours in seconds
    synthetic['time'] = [base_date + timedelta(seconds=int(sec)) for sec in time_intervals]
    
    # 2. Generate synthetic IP addresses (in integer format like your example)
    # Internal IPs (192.168.x.x range in integer: 3232235776 to 3232301311)
    synthetic['source_ip_int'] = np.random.randint(3232235776, 3232301311, n_samples)
    
    # External IPs (10.x.x.x range in integer)
    synthetic['destination_ip_int'] = np.random.randint(167772160, 184549375, n_samples)
    
    # 3. Generate ports based on service using the global PORT_MAPPING
    def map_port(service):
        if service in PORT_MAPPING:
            port = PORT_MAPPING[service]
            if pd.isna(port):
                return random.randint(1024, 65535)
            return port
        return random.randint(1, 1024)
    
    if 'service' in df.columns:
        synthetic['destination_port'] = df['service'].apply(map_port)
    else:
        synthetic['destination_port'] = np.random.randint(1, 65536, n_samples)
    
    # Source ports (ephemeral ports)
    synthetic['source_port'] = np.random.randint(49152, 65536, n_samples)
    
    # 4. Protocol mapping
    protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
    if 'protocol_type' in df.columns:
        synthetic['protocol'] = df['protocol_type'].map(protocol_map).fillna(0).astype(int)
    else:
        synthetic['protocol'] = np.random.choice([0, 1, 2], n_samples, p=[0.7, 0.2, 0.1])
    
    # 5. Use actual NSL-KDD features
    synthetic['duration'] = pd.to_numeric(df.get('duration', 0), errors='coerce').fillna(0)
    synthetic['packet_count'] = pd.to_numeric(df.get('count', 1), errors='coerce').clip(lower=1).astype(int)
    synthetic['bytes_sent'] = pd.to_numeric(df.get('src_bytes', 0), errors='coerce').clip(lower=0).astype(int)
    synthetic['bytes_received'] = pd.to_numeric(df.get('dst_bytes', 0), errors='coerce').clip(lower=0).astype(int)
    
    # 6. Labels
    if 'label' in df.columns:
        synthetic['label'] = df['label']
    elif 'class' in df.columns:
        synthetic['label'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    else:
        synthetic['label'] = 0
    
    # 7. Calculate bytes per packet
    synthetic['bytes_per_packet'] = (
        (synthetic['bytes_sent'] + synthetic['bytes_received']) / 
        synthetic['packet_count'].clip(lower=1)
    ).round(2)
    
    # 8. Format timestamp
    synthetic['time'] = synthetic['time'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # 9. Add some realistic variations based on attack types
    # For attacks, increase bytes/packets
    attack_mask = synthetic['label'] == 1
    if attack_mask.any():
        # Increase packet count for attacks
        synthetic.loc[attack_mask, 'packet_count'] = synthetic.loc[attack_mask, 'packet_count'] * np.random.uniform(1.5, 3.0, attack_mask.sum())
        synthetic.loc[attack_mask, 'packet_count'] = synthetic.loc[attack_mask, 'packet_count'].astype(int)
        
        # Increase duration for some attacks
        increase_duration = np.random.random(attack_mask.sum()) > 0.7
        synthetic.loc[attack_mask, 'duration'] = synthetic.loc[attack_mask, 'duration'] * np.where(
            increase_duration, np.random.uniform(2, 10, attack_mask.sum()), 1
        )
    
    # 10. Reorder columns to match your example
    columns_order = [
        'time', 'source_ip_int', 'destination_ip_int', 'source_port',
        'destination_port', 'protocol', 'duration', 'packet_count',
        'bytes_sent', 'bytes_received', 'label', 'bytes_per_packet'
    ]
    
    synthetic = synthetic[columns_order]
    
    # 11. Save to CSV
    synthetic.to_csv(output_csv, index=False)
    
    print(f"✓ Created network traffic format: {output_csv}")
    print(f"  Shape: {synthetic.shape}")
    print(f"  Normal traffic: {(synthetic['label'] == 0).sum():,}")
    print(f"  Attack traffic: {(synthetic['label'] == 1).sum():,}")
    print(f"  Time range: {synthetic['time'].min()} to {synthetic['time'].max()}")
    
    # Show sample
    print("\nSample of converted data:")
    print(synthetic.head(3).to_string())
    print("...")
    print(synthetic.tail(3).to_string())
    print("=" * 80)
    
    return synthetic

# ============================================
# PART 3: Main Execution
# ============================================

def main():
    print("NSL-KDD ARFF to Network Traffic Format Converter")
    print("=" * 80)
    
    # List of your ARFF files
    arff_files = [
        ('KDDTrain+.arff', 'train'),  # Assuming you have this
        ('KDDTest+.arff', 'test'),
        ('KDDTest-21.arff', 'test21')
    ]
    
    all_dfs = {}
    network_dfs = {}
    
    # Step 1: Convert ARFF to CSV
    for arff_file, name in arff_files:
        try:
            csv_file = f"nsl_kdd_{name}.csv"
            network_file = f"network_traffic_{name}.csv"
            
            print(f"\nProcessing {arff_file}...")
            
            # Check if file exists
            if not os.path.exists(arff_file):
                print(f"  File not found: {arff_file}")
                # Try with .txt extension
                txt_file = arff_file.replace('.arff', '.txt')
                if os.path.exists(txt_file):
                    print(f"  Found {txt_file}, using it instead")
                    arff_file = txt_file
                else:
                    continue
            
            # Convert ARFF to CSV
            df = convert_arff_to_csv(arff_file, csv_file)
            all_dfs[name] = df
            
            # Create network traffic format
            network_df = create_network_traffic_format(df, network_file, name)
            network_dfs[name] = network_df
            
        except Exception as e:
            print(f"✗ Error processing {arff_file}: {str(e)}")
    
    # Step 2: Combine all network data
    if network_dfs:
        print("\n" + "=" * 80)
        print("COMBINING ALL DATASETS")
        print("=" * 80)
        
        combined_network = pd.concat(network_dfs.values(), ignore_index=True)
        
        # Sort by time
        combined_network['time_dt'] = pd.to_datetime(combined_network['time'])
        combined_network = combined_network.sort_values('time_dt')
        combined_network = combined_network.drop('time_dt', axis=1)
        
        # Save combined dataset
        combined_file = "network_traffic_nslkdd_combined.csv"
        combined_network.to_csv(combined_file, index=False)
        
        print(f"✓ Combined all datasets into: {combined_file}")
        print(f"  Total samples: {len(combined_network):,}")
        print(f"  Normal: {(combined_network['label'] == 0).sum():,}")
        print(f"  Attacks: {(combined_network['label'] == 1).sum():,}")
        print(f"  Time span: {combined_network['time'].min()} to {combined_network['time'].max()}")
        
        # Show statistics
        print("\nDataset Statistics:")
        print("-" * 40)
        stats = combined_network.describe().round(2)
        print(stats[['duration', 'packet_count', 'bytes_sent', 'bytes_received', 'bytes_per_packet']])
        
        # Protocol distribution
        print("\nProtocol Distribution:")
        protocol_names = {0: 'TCP', 1: 'UDP', 2: 'ICMP'}
        combined_network['protocol_name'] = combined_network['protocol'].map(protocol_names)
        print(combined_network['protocol_name'].value_counts())
        
        # Common destination ports
        print("\nTop 10 Destination Ports:")
        top_ports = combined_network['destination_port'].value_counts().head(10)
        
        # Create reverse mapping for port to service name
        reverse_port_mapping = {}
        for service, port in PORT_MAPPING.items():
            if not pd.isna(port):
                reverse_port_mapping[int(port)] = service
        
        for port, count in top_ports.items():
            service_name = reverse_port_mapping.get(int(port), 'unknown')
            print(f"  Port {port} ({service_name}): {count:,} connections")
    
    # Step 3: Create a smaller sample for testing
    print("\n" + "=" * 80)
    print("CREATING SAMPLE DATASET FOR TESTING")
    print("=" * 80)
    
    if network_dfs:
        # Take 1000 random samples from combined data
        sample_size = min(1000, len(combined_network))
        sample_df = combined_network.sample(n=sample_size, random_state=42)
        sample_file = "network_traffic_sample_1000.csv"
        sample_df.to_csv(sample_file, index=False)
        
        print(f"✓ Created sample dataset: {sample_file}")
        print(f"  Sample size: {len(sample_df)}")
        print(f"  Normal in sample: {(sample_df['label'] == 0).sum()}")
        print(f"  Attacks in sample: {(sample_df['label'] == 1).sum()}")
        
        # Display first 5 rows like your example
        print("\nFirst 5 rows (formatted like your example):")
        for _, row in sample_df.head(5).iterrows():
            print(f"{row['time']},{row['source_ip_int']},{row['destination_ip_int']},"
                  f"{row['source_port']},{row['destination_port']},{row['protocol']},"
                  f"{row['duration']:.6f},{row['packet_count']},{row['bytes_sent']},"
                  f"{row['bytes_received']},{row['label']},{row['bytes_per_packet']}")

# ============================================
# PART 4: Quick Start Functions
# ============================================

def quick_convert_single_file(arff_file, output_csv="network_traffic.csv"):
    """Quick conversion for a single file"""
    print(f"Quick conversion of {arff_file} to {output_csv}")
    
    # First convert ARFF to basic CSV
    df = parse_arff_file(arff_file)
    df['label'] = df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Then create network format
    network_df = create_network_traffic_format(df, output_csv, "quick")
    return network_df

def convert_txt_to_csv(txt_file, output_csv="nsl_kdd.csv"):
    """Convert .txt version if ARFF parsing fails"""
    print(f"Converting {txt_file} to {output_csv}")
    
    # NSL-KDD has 42 columns
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
        'dst_host_srv_rerror_rate', 'label'
    ]
    
    df = pd.read_csv(txt_file, header=None, names=column_names)
    df.to_csv(output_csv, index=False)
    print(f"✓ Saved to {output_csv}")
    return df

# ============================================
# RUN THE CONVERSION
# ============================================

if __name__ == "__main__":
    print("Starting NSL-KDD conversion...")
    
    # Check what files we have
    files = os.listdir('.')
    arff_files = [f for f in files if f.endswith('.arff')]
    txt_files = [f for f in files if f.endswith('.txt') and 'KDD' in f]
    
    print(f"Found ARFF files: {arff_files}")
    print(f"Found TXT files: {txt_files}")
    
    # Run main conversion
    main()
    
    print("\n" + "=" * 80)
    print("CONVERSION COMPLETE!")
    print("=" * 80)
    print("\nGenerated files:")
    print("  - nsl_kdd_train.csv (if KDDTrain+.arff exists)")
    print("  - nsl_kdd_test.csv")
    print("  - nsl_kdd_test21.csv")
    print("  - network_traffic_train.csv")
    print("  - network_traffic_test.csv")
    print("  - network_traffic_test21.csv")
    print("  - network_traffic_nslkdd_combined.csv")
    print("  - network_traffic_sample_1000.csv")
    print("\nYour data is now ready for model training!")