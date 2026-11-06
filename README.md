Task 1: Netwrk Sniffer using python and Scapy

Explaination: This project capture the live traffic of network.It capture the 20 packet and
 Display the Source IP, Destination, Protocole, Port number, and payload.

How To run:
  Run command on terminal
  Sudo python3 Sniffer.py | tee output.txt

Result:
   Total Packet Capture 20
   Most packet were UDP. In the result we see that source ip 142.250.202.206 that is google's server ip .
   We verify this by nsloopkup command: nslookup  142.250.202.206
