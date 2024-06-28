import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from scapy.all import sniff, get_if_list, IP, UDP
import threading
import subprocess

# Initialize Tkinter window
window = tk.Tk()
window.title("LAN Analyzer")

# Function to perform Nmap scan
def nmap_scan():
    target = entry.get().strip()
    interface = interface_var.get().strip()
    try:
        # Run Nmap with sudo
        nmap_command = ['sudo', 'nmap', '-sS', '-Pn', '-e', interface, target]
        nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        
        def read_nmap_output(process):
            output_text.insert(tk.END, "Nmap Results:\n")
            for line in process.stdout:
                output_text.insert(tk.END, line)
            process.stdout.close()
            process.wait()

        threading.Thread(target=read_nmap_output, args=(nmap_process,)).start()

    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode('utf-8') if e.stderr else str(e)
        messagebox.showerror("Error", f"Nmap command returned non-zero exit status: {e.returncode}\n{error_message}")
    except FileNotFoundError:
        messagebox.showerror("Error", "Nmap command not found. Please install Nmap.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Function to perform P0F analysis
def p0f_scan():
    interface = interface_var.get().strip()
    valid_interfaces = get_if_list()
    if interface not in valid_interfaces:
        messagebox.showerror("Error", f"Invalid interface: {interface}. Please select a valid interface.")
        return

    try:
        # Command to execute p0f with sudo
        p0f_command = ['sudo', 'p0f', '-i', interface]
        p0f_process = subprocess.Popen(p0f_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

        def read_p0f_output(process):
            output_text.insert(tk.END, "P0F Analysis Results:\n")
            for line in process.stdout:
                output_text.insert(tk.END, f'P0F Output: {line}')
                # Observe traffic: You can process each line of output here for real-time analysis

        def handle_p0f_error(process):
            for line in process.stderr:
                output_text.insert(tk.END, f'P0F Error: {line}')
            process.stderr.close()

        threading.Thread(target=read_p0f_output, args=(p0f_process,), daemon=True).start()
        threading.Thread(target=handle_p0f_error, args=(p0f_process,), daemon=True).start()

    except subprocess.CalledProcessError as e:
        error_message = e.stderr.decode('utf-8') if e.stderr else str(e)
        messagebox.showerror("Error", f"P0F command returned non-zero exit status: {e.returncode}\n{error_message}")
    except FileNotFoundError:
        messagebox.showerror("Error", "P0F command not found. Please install P0F via Homebrew.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Function to perform Scapy packet sniffing
def scapy_sniff():
    interface = interface_var.get().strip()

    def packet_callback(packet):
        if IP in packet and UDP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            payload = packet[UDP].payload  # Get the payload (data) of the UDP packet
            length = len(packet)  # Get the length of the packet

            output_text.insert(tk.END, f'Scapy Packet:\n')
            output_text.insert(tk.END, f'Source IP: {src_ip}, Source Port: {src_port}\n')
            output_text.insert(tk.END, f'Destination IP: {dst_ip}, Destination Port: {dst_port}\n')
            output_text.insert(tk.END, f'Protocol: {protocol}\n')
            output_text.insert(tk.END, f'Payload: {payload}\n')
            output_text.insert(tk.END, f'Packet Length: {length} bytes\n\n')

    try:
        sniff(iface=interface, prn=packet_callback, count=10, timeout=10)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

# Function to run Scapy sniffing in a separate thread
def scapy_sniff_thread():
    thread = threading.Thread(target=scapy_sniff)
    thread.start()

# Get list of valid network interfaces
valid_interfaces = get_if_list()

# Layout for input and buttons
entry_label = tk.Label(window, text="Target (IP, Range, Subnet, Hostname):")
entry_label.pack()

entry = tk.Entry(window, width=50)
entry.pack()

interface_label = tk.Label(window, text="Select Interface:")
interface_label.pack()

interface_var = tk.StringVar()
interface_dropdown = ttk.Combobox(window, textvariable=interface_var, values=valid_interfaces, state="readonly")
interface_dropdown.pack()

nmap_button = tk.Button(window, text="Nmap Scan", command=nmap_scan)
nmap_button.pack()

p0f_button = tk.Button(window, text="P0F Analysis", command=p0f_scan)
p0f_button.pack()

scapy_button = tk.Button(window, text="Scapy Sniff", command=scapy_sniff_thread)
scapy_button.pack()

# Output area
output_text = scrolledtext.ScrolledText(window, width=80, height=20)
output_text.pack()

# Start the Tkinter event loop
window.mainloop()
