### PyPacketParser

This program captures packets using scapy with the specificied the following fields:
-c Determines how many packets will be captured
-f Uses the BPF Filter to specifcy which packets to capture
-i Determines what interface it will capture packets on.

Only select packets were implemented. These are:
- TCP (IPV4)
- UDP (IPV4)
- ICMP(IPV4)
- ARP Table

### Running the Program
Clone the repo:
```git clone https://github.com/Matirix/PyPacketCapture.git```
Run with the command:
```python3 main.py -c <count> -f <filter> -i <interface>```

### Troubleshooting
A virtual python environment maybe required to run the program with scapy.
Step 1: Make a python program
```python -m venv myenv```
Step 2: Activate it
```source ./myenv/bin/activate```
Step 3: Install Scapy
```pip install scapy```
Step 4: Run the program.
```python3 main.py -c <count> -f <filter> -i <interface>```
