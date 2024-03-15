from scapy.all import sniff, IP, Ether
from datetime import datetime
import requests
import logging

# logging visible in homebridge protocol
logging.basicConfig(filename='/var/lib/homebridge/homebridge.log', level=logging.INFO)

# IP of doorstation (not doorbell!)
SOURCE_IP = 'xxx.xxx.xxx.xxx'

# target IP (should always be the same)
DESTINATION_IP = '224.0.0.22'

# MulticastIP for doorbell event (should start with 239.xxx.xxx.xxx and the rest from your doorstation)
MULTICAST_IP_EVENT = '239.xxx.xxx.xxx'

# MulticastIP for reset (should always be the same)
MULTICAST_IP_RESET = '239.255.255.250'

# HTTP event e.g. for camera.ui
URL = "http://xxx.xxx.xxx.xxx:port/doorbell?mydoor"

hex_address_event = ':'.join(format(int(part), '02x') for part in MULTICAST_IP_EVENT.split('.'))
hex_address_reset = ':'.join(format(int(part), '02x') for part in MULTICAST_IP_RESET.split('.'))

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        igmp_payload = extract_igmp_payload(packet)
        multicast_address = extract_multicast_address(igmp_payload)
        
        # check for reset event
        if (src_ip == SOURCE_IP and dst_ip == DESTINATION_IP and multicast_address == hex_address_reset):
            print(f"{timestamp} - Cache is reset and started again.")
            global sniffed_packets
            sniffed_packets = [] # Reset sniffer cache
            if len(sniffed_packets) == 0:
                print(f"{timestamp} - Sniffer cache has been reset successfully.")
            else:
                logging.error(f"{timestamp} - Error resetting the sniffer cache.")
            return
        
        # check for doorbell event
        if (src_ip == SOURCE_IP and dst_ip == DESTINATION_IP and multicast_address == hex_address_event):
            print(f"{timestamp} - Receive event.")
            trigger_action(timestamp)

def extract_igmp_payload(packet):
    if Ether in packet and IP in packet:
        payload = packet[IP].payload
        if payload and payload.haslayer('Raw'):
            return payload['Raw'].load.hex()  # Convert payload to hexadecimal string
    return "Unknown"

def extract_multicast_address(payload):
    if payload:
        multicast_address_hex = payload[24:36]  # Extract multicast address hex string
        multicast_address = ':'.join([multicast_address_hex[i:i+2] for i in range(0, len(multicast_address_hex), 2)])
        return multicast_address
    return "Unknown"

def trigger_action(timestamp):
    try:
        response = requests.get(URL)
        if response.status_code == 200:
            logging.info(f"{timestamp} - Successful: HTTP GET request sent successfully.")
        else:
            logging.error(f"{timestamp} - Error: HTTP GET request could not be sent.")
    except Exception as e:
        logging.error(f"{timestamp} - Fehler:", e, "(Debug)")

def main():
    global sniffed_packets
    sniffed_packets = []
    while True:
        sniff(prn=process_packet, filter=f"ip host {DESTINATION_IP}")

if __name__ == "__main__":
    main()