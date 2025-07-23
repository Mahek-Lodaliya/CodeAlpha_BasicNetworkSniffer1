from scapy.all import sniff, IP
import os
import ctypes

# Check for administrator rights (Windows only)
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to process captured packets
def process_packet(packet):
    print("=" * 50)

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"[+] Source IP      : {src_ip}")
        print(f"[+] Destination IP : {dst_ip}")

        if proto == 6:
            print("[+] Protocol       : TCP")
        elif proto == 17:
            print("[+] Protocol       : UDP")
        elif proto == 1:
            print("[+] Protocol       : ICMP")
        else:
            print("[+] Protocol       : Other")

        try:
            payload = bytes(packet[IP].payload)
            if payload:
                print(f"[+] Payload        : {payload.decode(errors='ignore')}")
            else:
                print("[+] Payload        : <empty>")
        except Exception as e:
            print(f"[!] Error decoding payload: {e}")
    else:
        print("[-] Non-IP Packet")

# Main execution
if __name__ == "__main__":
    if not is_admin():
        print("[!] Run this script as Administrator.")
        input("Press Enter to exit...")
        exit()

    print("[*] Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        sniff(prn=process_packet, store=False)
    except Exception as e:
        print(f"[!] Error: {e}")
        input("Press Enter to exit...")
