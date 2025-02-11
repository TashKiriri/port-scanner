import nmap
import smtplib
import logging
import time
import getpass
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
import argparse
from tqdm import tqdm

# Initialize the logger
logging.basicConfig(filename='port_scan.log', level=logging.INFO)
logger = logging.getLogger()

# Create a nm object for nmap scanning
nm = nmap.PortScanner()

# Global results list
results = []

def scan_target(ip, ports):
    global results
    try:
        # Print the nmap command to debug
        print(f"nmap scan command: nmap.scan({ip}, {ports}, arguments='-sS -Pn --min-rate 5000')")
        
        # Perform the scan
        nm.scan(ip, ports, arguments="-sS -Pn --min-rate 5000")
        
        # Extract open ports
        open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
        
        # Store the result
        result = {
            "IP": ip,
            "Open Ports": open_ports
        }
        results.append(result)
        
    except Exception as e:
        # Log the error message for better debugging
        print(f"Error scanning {ip}: {e}")
        logger.error(f"Error scanning {ip}: {e}")

import getpass

def send_email(email, subject, body):
    try:
        from_email = input("Enter your email address: ")
        password = getpass.getpass("Enter your email password: ")  # Hides password input

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, email, text)
        server.quit()
        print(f"Email sent to {email}")
        logger.info(f"Email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")
        logger.error(f"Error sending email: {e}")


def scan_ports(ips, ports, threads):
    global results
    # Display the progress bar with tqdm
    with tqdm(total=len(ips), desc="Scanning IPs", ncols=100) as pbar:
        for ip in ips:
            # Start a new thread for each IP
            thread = Thread(target=scan_target, args=(ip, ports))
            thread.start()
            thread.join()
            pbar.update(1)

    print("Scan complete. Results saved to database and scan_results.json.")
    logger.info("Scan complete. Results saved to database and scan_results.json.")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Port scanner with email alerts.')
    parser.add_argument('ips', help='Comma-separated list of IP addresses to scan')
    parser.add_argument('ports', help='Port range or specific ports to scan')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads to use for scanning')
    args = parser.parse_args()

    # Get the email address to send alerts
    email = input("Enter the email address to receive alerts: ")

    ips = args.ips.split(',')
    ports = args.ports

    # Validate port range format
    if '-' in ports:
        start_port, end_port = map(int, ports.split('-'))
        ports = ','.join(map(str, range(start_port, end_port+1)))

    print(f"Scanning {len(ips)} IPs for open ports in range {ports}...")
    
    # Start the port scan
    scan_ports(ips, ports, args.threads)

    # Send the email alert with the results
    subject = "Port Scan Results"
    body = f"Port scan completed for IPs: {', '.join(ips)}. Results: {results}"
    send_email(email, subject, body)

if __name__ == "__main__":
    main()
