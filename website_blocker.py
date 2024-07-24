import tkinter as tk
from tkinter import messagebox
import socket
import subprocess

def block_websites():
    websites = website_entry.get().strip().split(',')
    for website in websites:
        website = website.strip()
        if not website:
            continue
        try:
            ip_addresses = socket.gethostbyname_ex(website)[2]
            for ip_address in ip_addresses:
                if ip_address in website_ip_map:
                    website_ip_map[ip_address].append(website)
                else:
                    website_ip_map[ip_address] = [website]
                block_command = ['sudo', 'pfctl', '-t', 'blocked_websites', '-T', 'add', ip_address]
                result = subprocess.run(block_command, check=True, capture_output=True, text=True)
                output_text.insert(tk.END, f"Blocked website: {website} (IP: {ip_address})\n")
                output_text.see(tk.END)

        except socket.gaierror:
            messagebox.showerror("Error", f"Could not resolve IP address for {website}.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to block website {website}: {str(e)}\n{e.output}")

# Create main window
root = tk.Tk()
root.title("Website Blocker")

# Create and pack widgets
tk.Label(root, text="Enter websites to block (comma-separated):").pack()
website_entry = tk.Entry(root, width=50)
website_entry.pack()

tk.Button(root, text="Block Websites", command=block_websites).pack()

output_text = tk.Text(root, height=10, width=50)
output_text.pack()

# Initialize website_ip_map
website_ip_map = {}

root.mainloop()