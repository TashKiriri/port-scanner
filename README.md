# port-scanner
🔍 Python Port Scanner with Email Alerts
📌 Overview
This script scans a list of IP addresses for open ports using Nmap and sends email alerts with the scan results. It uses multi-threading for faster scanning and provides a progress bar for better visibility.

📦 Dependencies (What Needs to Be Installed)
Before running this script, you need to install the required Python modules and Nmap.

1️⃣ Install Python Packages
Run the following command to install all required dependencies:

sh
pip install nmap tqdm smtplib email
2️⃣ Install Nmap
Since this script relies on Nmap, you must have it installed on your system.

Windows: Download and install from Nmap Official Site.
Linux/macOS: Install using the package manager:
sh
sudo apt install nmap  # For Debian-based systems
brew install nmap  # For macOS
🛠 How It Works
1️⃣ Import Required Modules
The script imports various modules to handle:

Nmap scanning (nmap)
Multi-threading (threading.Thread)
Email sending (smtplib, MIMEText, MIMEMultipart)
Logging (logging)
Argument parsing (argparse)
Progress bar display (tqdm)
Hiding password input (getpass)
2️⃣ Port Scanning with Nmap
The script initializes an Nmap scanner (nm = nmap.PortScanner()) and defines a function to scan a target IP:

python
def scan_target(ip, ports):
    global results
    try:
        # Perform the scan
        nm.scan(ip, ports, arguments="-sS -Pn --min-rate 5000")
        
        # Extract open ports
        open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
        
        # Store the result
        result = {"IP": ip, "Open Ports": open_ports}
        results.append(result)

    except Exception as e:
        print(f"Error scanning {ip}: {e}")
        logger.error(f"Error scanning {ip}: {e}")
📌 Explanation:

The function performs an Nmap scan with the -sS -Pn --min-rate 5000 options:
-sS → Stealth scan (SYN scan)
-Pn → Disables host discovery (assumes the target is online)
--min-rate 5000 → Increases scan speed
Extracts open TCP ports and logs errors if any occur.
3️⃣ Multi-Threaded Scanning for Faster Results
python
def scan_ports(ips, ports, threads):
    global results
    with tqdm(total=len(ips), desc="Scanning IPs", ncols=100) as pbar:
        for ip in ips:
            thread = Thread(target=scan_target, args=(ip, ports))
            thread.start()
            thread.join()
            pbar.update(1)
📌 Explanation:

Uses multi-threading to scan multiple IPs in parallel.
Displays a progress bar using tqdm for better tracking.
4️⃣ Secure Email Alerts
Once the scan is complete, results are emailed securely to the user:

python
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
        server.sendmail(from_email, email, msg.as_string())
        server.quit()
        
        print(f"Email sent to {email}")
        logger.info(f"Email sent to {email}")
    except Exception as e:
        print(f"Error sending email: {e}")
        logger.error(f"Error sending email: {e}")
📌 Explanation:

Uses getpass.getpass() to hide the password input.
Sends results via email using SMTP (smtplib).
Logs errors in case email sending fails.
5️⃣ Running the Script
python
Copy
Edit
python port_scanner.py "192.168.1.1,192.168.1.2" "20-1000" --threads 10
📌 Explanation:

Scans IPs 192.168.1.1 and 192.168.1.2 for ports 20-1000 using 10 threads.
🔮 Future Improvements
Save results to a database instead of JSON.
Add UDP scanning support.
Create a GUI version using Flask.
💡 Final Notes
This script is a powerful yet simple port scanner with email alerts.
Make sure to run it with administrator/root privileges for better scanning results. 🚀

Let me know if you need any modifications! 🔥
