import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
import threading
import subprocess
import socket
from collections import deque
from datetime import datetime

# Initialize Tkinter window
window = tk.Tk()
window.title("LAN Analyzer")

# Global variables
current_process = None
scapy_thread = None
scapy_stop_event = threading.Event()

# Initialize the mapping dictionary
website_ip_map = {}

# Queue to hold last seen packets
recent_packets = deque(maxlen=100)

def safe_insert_text(widget, text):
    widget.after(0, lambda: widget.insert(tk.END, text))

def stop_current_process():
    global current_process
    global scapy_thread
    scapy_stop_event.set()  # Signal to stop sniffing

    if current_process and current_process.poll() is None:  # Check if the process is running
        current_process.terminate()
        safe_insert_text(output_text, "Process terminated.\n")
        current_process = None

    if scapy_thread and scapy_thread.is_alive():
        scapy_thread.join(timeout=5)  # Give the thread time to terminate gracefully
        if scapy_thread.is_alive():
            safe_insert_text(output_text, "Scapy sniffing did not stop gracefully.\n")
        else:
            safe_insert_text(output_text, "Scapy sniffing stopped.\n")

def nmap_scan():
    global current_process
    stop_current_process()  # Stop any currently running process

    target = entry.get().strip()
    interface = interface_var.get().strip()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return
    if not interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return

    try:
        nmap_command = ['sudo', 'nmap', '-sS', '-Pn', '-e', interface, target]
        current_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        def read_nmap_output(process):
            safe_insert_text(output_text, "Nmap Results:\n")
            for line in process.stdout:
                if "Nmap" in line and "https" in line:
                    continue  # Skip the line containing the URL
                safe_insert_text(output_text, line)
            process.stdout.close()
            process.wait()

        threading.Thread(target=read_nmap_output, args=(current_process,)).start()

    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e)
        messagebox.showerror("Error", f"Nmap command returned non-zero exit status: {e.returncode}\n{error_message}")
    except FileNotFoundError:
        messagebox.showerror("Error", "Nmap command not found. Please install Nmap.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def p0f_scan():
    global current_process
    stop_current_process()  # Stop any currently running process

    interface = interface_var.get().strip()
    valid_interfaces = get_if_list()
    if interface not in valid_interfaces:
        messagebox.showerror("Error", f"Invalid interface: {interface}. Please select a valid interface.")
        return

    try:
        p0f_command = ['/opt/homebrew/sbin/p0f', '-i', interface]  # Use the full path to p0f
        current_process = subprocess.Popen(p0f_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        def read_p0f_output(process):
            safe_insert_text(output_text, "P0F Analysis Results:\n")
            for line in iter(process.stdout.readline, ''):
                safe_insert_text(output_text, f'P0F Output: {line}')
            process.stdout.close()
            process.wait()

        def handle_p0f_error(process):
            for line in process.stderr:
                safe_insert_text(output_text, f'P0F Error: {line}')
            process.stderr.close()

        threading.Thread(target=read_p0f_output, args=(current_process,), daemon=True).start()
        threading.Thread(target=handle_p0f_error, args=(current_process,), daemon=True).start()

    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e)
        messagebox.showerror("Error", f"P0F command returned non-zero exit status: {e.returncode}\n{error_message}")
    except FileNotFoundError:
        messagebox.showerror("Error", "P0F command not found. Please install P0F.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def scapy_sniff():
    interface = interface_var.get().strip()
    if not interface:
        messagebox.showerror("Error", "Please select a network interface.")
        return

    safe_insert_text(output_text, f"Starting sniffing on interface: {interface}\n")

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto

            # Identify the protocol and extract relevant information
            if TCP in packet:
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = packet[TCP].payload
            elif UDP in packet:
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                payload = packet[UDP].payload
            elif ICMP in packet:
                protocol = "ICMP"
                src_port = "N/A"
                dst_port = "N/A"
                payload = packet[ICMP].payload
            else:
                protocol = "Other"
                src_port = "N/A"
                dst_port = "N/A"
                payload = "N/A"

            length = len(packet)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            packet_info = (src_ip, dst_ip, protocol, src_port, dst_port, length, timestamp)

            if packet_info not in recent_packets:
                recent_packets.append(packet_info)
                safe_insert_text(output_text, f'{timestamp} - Scapy Packet:\n')
                safe_insert_text(output_text, f'Source IP: {src_ip}, Source Port: {src_port}\n')
                safe_insert_text(output_text, f'Destination IP: {dst_ip}, Destination Port: {dst_port}\n')
                safe_insert_text(output_text, f'Protocol: {protocol}\n')
                safe_insert_text(output_text, f'Payload: {payload}\n')
                safe_insert_text(output_text, f'Packet Length: {length} bytes\n\n')

    def sniff_packets():
        safe_insert_text(output_text, f"Sniffing started on interface: {interface}\n")
        while not scapy_stop_event.is_set():
            try:
                sniff(iface=interface, prn=packet_callback, timeout=10)
                safe_insert_text(output_text, "Sniffing...\n")
            except Exception as e:
                safe_insert_text(output_text, f"Scapy error: {str(e)}\n")
                break
        safe_insert_text(output_text, "Sniffing stopped.\n")

    global scapy_thread
    scapy_stop_event.clear()  # Clear any existing stop event
    scapy_thread = threading.Thread(target=sniff_packets)
    scapy_thread.start()

def scapy_sniff_thread():
    stop_current_process()  # Stop any currently running process
    threading.Thread(target=scapy_sniff).start()

def block_websites():
    websites = website_entry.get().strip().split(',')
    for website in websites:
        website = website.strip()
        if not website:
            continue
        try:
            # Resolve all IPs for the website
            ip_addresses = socket.gethostbyname_ex(website)[2]
            for ip_address in ip_addresses:
                if ip_address in website_ip_map:
                    website_ip_map[ip_address].append(website)
                else:
                    website_ip_map[ip_address] = [website]
                block_command = ['sudo', 'pfctl', '-t', 'blocked_websites', '-T', 'add', ip_address]
                result = subprocess.run(block_command, check=True, capture_output=True, text=True)
                safe_insert_text(output_text, f"Blocked website: {website} (IP: {ip_address})\n")
                if result.returncode == 0:
                    safe_insert_text(output_text, f"Successfully blocked IP: {ip_address} for website: {website}\n")
                else:
                    safe_insert_text(output_text, f"Failed to block IP: {ip_address} for website: {website}. Error: {result.stderr}\n")

        except socket.gaierror:
            messagebox.showerror("Error", f"Could not resolve IP address for {website}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to block website {website}: {str(e)}\n{e.output}")

def unblock_websites():
    websites = website_entry.get().strip().split(',')
    for website in websites:
        website = website.strip()
        if not website:
            continue
        try:
            # Resolve all IPs for the website
            ip_addresses = socket.gethostbyname_ex(website)[2]
            for ip_address in ip_addresses:
                unblock_command = ['sudo', 'pfctl', '-t', 'blocked_websites', '-T', 'delete', ip_address]
                result = subprocess.run(unblock_command, check=True, capture_output=True, text=True)
                safe_insert_text(output_text, f"Unblocked website: {website} (IP: {ip_address})\n")
                if ip_address in website_ip_map:
                    if website in website_ip_map[ip_address]:
                        website_ip_map[ip_address].remove(website)
                    if not website_ip_map[ip_address]:
                        del website_ip_map[ip_address]

                if result.returncode == 0:
                    safe_insert_text(output_text, f"Successfully unblocked IP: {ip_address} for website: {website}\n")
                else:
                    safe_insert_text(output_text, f"Failed to unblock IP: {ip_address} for website: {website}. Error: {result.stderr}\n")

        except socket.gaierror:
            messagebox.showerror("Error", f"Could not resolve IP address for {website}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to unblock website {website}: {str(e)}\n{e.output}")

def show_blocked_websites():
    try:
        show_command = ['sudo', 'pfctl', '-t', 'blocked_websites', '-T', 'show']
        result = subprocess.run(show_command, check=True, capture_output=True, text=True)
        blocked_ips = result.stdout.strip().split('\n')
        
        blocked_text.delete(1.0, tk.END)
        for ip in blocked_ips:
            if ip in website_ip_map:
                for website in website_ip_map[ip]:
                    safe_insert_text(blocked_text, f"{ip} ({website})\n")
            else:
                safe_insert_text(blocked_text, f"{ip}\n")
    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e)
        safe_insert_text(output_text, f"Failed to show blocked websites: {error_message}\n")
    except Exception as e:
        safe_insert_text(output_text, f"An unexpected error occurred: {str(e)}\n")

# Define UI Elements
interface_var = tk.StringVar()
interface_label = tk.Label(window, text="Network Interface:")
interface_label.pack()

interfaces = get_if_list()
interface_menu = ttk.Combobox(window, textvariable=interface_var, values=interfaces)
interface_menu.pack()

entry_label = tk.Label(window, text="Target IP Address:")
entry_label.pack()
entry = tk.Entry(window)
entry.pack()

website_label = tk.Label(window, text="Websites to Block/Unblock (comma-separated):")
website_label.pack()
website_entry = tk.Entry(window)
website_entry.pack()

nmap_button = tk.Button(window, text="Run Nmap Scan", command=nmap_scan)
nmap_button.pack()

p0f_button = tk.Button(window, text="Run P0F Analysis", command=p0f_scan)
p0f_button.pack()

scapy_button = tk.Button(window, text="Run Scapy Sniff", command=scapy_sniff_thread)
scapy_button.pack()

block_button = tk.Button(window, text="Block Websites", command=block_websites)
block_button.pack()

unblock_button = tk.Button(window, text="Unblock Websites", command=unblock_websites)
unblock_button.pack()

show_button = tk.Button(window, text="Show Blocked Websites", command=show_blocked_websites)
show_button.pack()

stop_button = tk.Button(window, text="Stop Current Process", command=stop_current_process)
stop_button.pack()

output_text = scrolledtext.ScrolledText(window, width=120, height=20)
output_text.pack()

blocked_label = tk.Label(window, text="Blocked Websites:")
blocked_label.pack()

blocked_text = scrolledtext.ScrolledText(window, width=40, height=10)
blocked_text.pack()

# Run the Tkinter event loop
window.mainloop()
