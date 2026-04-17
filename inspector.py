import psutil
import pefile
import os
import binascii
import re
import hashlib
import tempfile
import ctypes

def analyze_process_deep(pid: int):
    results = {
        "pid": pid,
        "success": False,
        "error": None,
        "ram_usage_mb": 0.0,
        "imports": {},
        "exports": [],
        "pe_headers": {},
        "sha256": "Unknown",
        "tokens": {"integrity": "Unknown", "privileges": []},
        "handles": {"files": [], "sockets": [], "dlls": []}
    }
    
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        
        # Get deep RAM usage
        mem_info = proc.memory_info()
        results["ram_usage_mb"] = mem_info.rss / (1024 * 1024)
        
        # SHA-256
        if exe_path and os.path.exists(exe_path):
            with open(exe_path, "rb") as f:
                results["sha256"] = hashlib.sha256(f.read()).hexdigest()
                
        # Tokens
        try:
            import win32api
            import win32security
            import win32con
            
            h_proc_win = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
            h_token = win32security.OpenProcessToken(h_proc_win, win32security.TOKEN_QUERY)
            
            # Integrity
            token_info = win32security.GetTokenInformation(h_token, win32security.TokenIntegrityLevel)
            sid = token_info[0]
            sid_str = win32security.ConvertSidToStringSid(sid)
            
            integrity_map = {
                "S-1-16-4096": "Low",
                "S-1-16-8192": "Medium",
                "S-1-16-12288": "High",
                "S-1-16-16384": "System",
                "S-1-16-20480": "ProtectedProcess"
            }
            results["tokens"]["integrity"] = integrity_map.get(sid_str, sid_str)
            
            # Privileges
            privs = win32security.GetTokenInformation(h_token, win32security.TokenPrivileges)
            for luid, flags in privs:
                name = win32security.LookupPrivilegeName(None, luid)
                if flags & win32security.SE_PRIVILEGE_ENABLED:
                    results["tokens"]["privileges"].append(name)
                    
            win32api.CloseHandle(h_token)
            win32api.CloseHandle(h_proc_win)
        except Exception as e:
            results["tokens"]["error"] = f"Win32 API error: {e}"
            
        # Handles (Files, Sockets, DLLs)
        try:
            for f in proc.open_files():
                results["handles"]["files"].append(f.path)
        except: pass
        
        try:
            for c in proc.connections():
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "None"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "None"
                t_name = "TCP" if c.type == 1 else ("UDP" if c.type == 2 else str(c.type))
                results["handles"]["sockets"].append(f"{t_name} {c.status} {laddr} -> {raddr}")
        except: pass
        
        try:
            for m in proc.memory_maps():
                if m.path and m.path not in results["handles"]["dlls"]:
                    results["handles"]["dlls"].append(m.path)
        except: pass
        
        # Static Analysis of the PE File
        if exe_path and os.path.exists(exe_path):
            try:
                pe = pefile.PE(exe_path, fast_load=True)
                
                # We need to parse data directories to get imports/exports
                pe.parse_data_directories( directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
                ])
                
                # Map Imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        imported_funcs = []
                        for imp in entry.imports:
                            if imp.name:
                                imported_funcs.append(imp.name.decode('utf-8', errors='ignore'))
                            else:
                                imported_funcs.append(f"Ordinal[{imp.ordinal}]")
                        results["imports"][dll_name] = imported_funcs
                        
                # Map Exports
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name:
                            results["exports"].append(exp.name.decode('utf-8', errors='ignore'))
                            
                # Helper for struct formatting
                def make_struct_string(obj, struct_name):
                    lines = [f"typedef struct _{struct_name} {{"]
                    if hasattr(obj, 'dump'):
                        for field in obj.dump():
                            if field.startswith("[") or ":" not in field:
                                continue
                            try:
                                parts = field.split(":", 1)
                                name_part = parts[0].split()[-1]
                                value_part = parts[1].strip()
                                lines.append(f"    DWORD {name_part:<16}; // {value_part}")
                            except:
                                lines.append(f"    // {field}")
                    lines.append(f"}} {struct_name};")
                    return "\n".join(lines)

                # Dump Hex Sections
                results["pe_headers"]["DOS_HEADER"] = {
                    "struct": make_struct_string(pe.DOS_HEADER, "IMAGE_DOS_HEADER"),
                    "hex": format_hex_dump(pe.header[:64])
                }
                
                if hasattr(pe, 'FILE_HEADER'):
                    nt_data = pe.header[pe.DOS_HEADER.e_lfanew:pe.DOS_HEADER.e_lfanew+256]
                    results["pe_headers"]["FILE_HEADER"] = {
                        "struct": make_struct_string(pe.FILE_HEADER, "IMAGE_FILE_HEADER"),
                        "hex": format_hex_dump(nt_data)
                    }
                
                for section in pe.sections:
                    sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                    data = section.get_data()
                    results["pe_headers"][f"SECTION {sec_name}"] = {
                        "struct": make_struct_string(section, f"IMAGE_SECTION_HEADER_{sec_name}"),
                        "hex": format_hex_dump(data[:256])
                    }

                pe.close()
                results["success"] = True
                
            except Exception as pe_err:
                results["error"] = f"PE Parsing Error: {str(pe_err)}"
        else:
            results["error"] = "Process has no accessible executable path."
            
    except psutil.NoSuchProcess:
        results["error"] = "Process no longer running."
    except psutil.AccessDenied:
        results["error"] = "Access Denied (Try running as Administrator)."
    except Exception as e:
        results["error"] = str(e)
        
    return results

def format_hex_dump(data: bytes) -> str:
    if not data: return "Empty or restricted section."
    hex_dump = ""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join([f"{b:02x}" for b in chunk])
        ascii_str = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])
        hex_dump += f"{i:08x}  {hex_str:<48}  |{ascii_str}|\n"
    return hex_dump

def extract_strings(pid: int):
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        if not exe_path or not os.path.exists(exe_path):
            return {"error": "Invalid executable path"}
        
        with open(exe_path, "rb") as f:
            data = f.read()
            
        strings = re.findall(b'[\x20-\x7e]{5,}', data)
        str_list = [s.decode('ascii', errors='ignore') for s in strings[:500]]
        return {"strings": str_list}
    except Exception as e:
        return {"error": str(e)}

def generate_minidump(pid: int):
    try:
        dbghelp = ctypes.windll.DbgHelp
        kernel32 = ctypes.windll.kernel32
        
        PROCESS_ALL_ACCESS = 0x1F0FFF
        h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_proc:
            return None
            
        dmp_fd, dmp_path = tempfile.mkstemp(suffix=".dmp", prefix=f"proc_{pid}_")
        os.close(dmp_fd)
        
        GENERIC_WRITE = 0x40000000
        FILE_SHARE_WRITE = 0x00000002
        CREATE_ALWAYS = 2
        FILE_ATTRIBUTE_NORMAL = 0x80
        
        h_file = kernel32.CreateFileA(
            dmp_path.encode('ascii'),
            GENERIC_WRITE,
            0,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
        
        if h_file == -1:
            kernel32.CloseHandle(h_proc)
            return None
            
        success = dbghelp.MiniDumpWriteDump(
            h_proc,
            pid,
            h_file,
            0,
            None, None, None
        )
        
        kernel32.CloseHandle(h_file)
        kernel32.CloseHandle(h_proc)
        
        if success:
            return dmp_path
        return None
    except Exception:
        return None
