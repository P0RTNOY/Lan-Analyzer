Nmap:
What it does: Scans the network to identify open and vulnerable devices. The user inputs a target IP address and the network interface to use. 
The code runs an Nmap scan using the command sudo nmap -Pn -sS -e [interface] [target].
How it works: Stops any currently running process, checks if the user provided a valid IP address and network interface, runs the Nmap command in a new subprocess, reads the output, and displays it in the GUI's text box.

P0F:
What it does: Analyzes network traffic to identify the operating systems of devices on the network.
The user selects a network interface to analyze.
How it works: Stops any currently running process, checks if the user selected a valid network interface, runs the P0F command in a new subprocess, reads the output, and displays it in the GUI's text box.

Scapy:
What it does: Listens to network traffic and displays details about the captured packets.
The user selects a network interface to listen to.
How it works: Stops any currently running process, starts listening on the selected network interface, defines a callback function to handle and display packet details, and shows the packets in the GUI's text box. Listening can be stopped by pressing a "Stop Current Process" button.

Block Websites:
What it does: Blocks websites by adding their IP addresses to a block list in PF (Packet Filter).
The user inputs website names in the GUI.
How it works: The user inputs website names in the GUI, the code queries the DNS server for their IP addresses, adds the IPs to the blocked_websites list in PF using the command sudo pfctl -t blocked_websites -T add, and displays a success or failure message in the GUI's text box.
