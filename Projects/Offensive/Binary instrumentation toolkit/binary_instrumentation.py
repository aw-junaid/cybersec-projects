#!/usr/bin/env python3
import ctypes
import struct
import threading
import time
from ctypes import wintypes
import platform
import sys
import os

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

class WindowsInstrumentation:
    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)
        self.ntdll = ctypes.WinDLL('ntdll', use_last_error=True)
        
        # Setup function prototypes
        self._setup_prototypes()
        
    def _setup_prototypes(self):
        """Setup Windows API function prototypes"""
        # Process functions
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        
        self.kernel32.VirtualAllocEx.restype = wintypes.LPVOID
        self.kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
        
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        self.kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        
        self.kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        self.kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        
        # Memory functions
        self.kernel32.VirtualProtectEx.restype = wintypes.BOOL
        self.kernel32.VirtualProtectEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        
        # Module enumeration
        self.psapi.EnumProcessModules.restype = wintypes.BOOL
        self.psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        
        self.psapi.GetModuleBaseNameA.restype = wintypes.DWORD
        self.psapi.GetModuleBaseNameA.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.c_char_p, wintypes.DWORD]
        
        self.psapi.GetModuleInformation.restype = wintypes.BOOL
        self.psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.c_void_p, wintypes.DWORD]
    
    def attach_process(self, pid=None, process_name=None):
        """Attach to a process by PID or name"""
        if pid:
            process_handle = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            if process_handle:
                print(f"[+] Attached to process PID: {pid}")
                return process_handle
        elif process_name:
            # Find process by name (simplified)
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'].lower() == process_name.lower():
                    return self.attach_process(pid=proc.info['pid'])
        
        print(f"[-] Failed to attach to process")
        return None
    
    def enumerate_modules(self, process_handle):
        """Enumerate loaded modules in target process"""
        modules = []
        h_modules = (wintypes.HMODULE * 1024)()
        cb_needed = wintypes.DWORD()
        
        if self.psapi.EnumProcessModules(process_handle, h_modules, ctypes.sizeof(h_modules), ctypes.byref(cb_needed)):
            module_count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
            
            for i in range(module_count):
                module_handle = h_modules[i]
                module_name = ctypes.create_string_buffer(256)
                
                if self.psapi.GetModuleBaseNameA(process_handle, module_handle, module_name, ctypes.sizeof(module_name)):
                    modules.append({
                        'handle': module_handle,
                        'name': module_name.value.decode(),
                        'base_address': module_handle
                    })
        
        return modules
    
    def allocate_remote_memory(self, process_handle, size, address=None):
        """Allocate memory in remote process"""
        allocated_memory = self.kernel32.VirtualAllocEx(
            process_handle,
            address,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        
        if allocated_memory:
            print(f"[+] Allocated {size} bytes at 0x{allocated_memory:x}")
            return allocated_memory
        else:
            print(f"[-] Failed to allocate remote memory")
            return None
    
    def write_remote_memory(self, process_handle, address, data):
        """Write data to remote process memory"""
        written = ctypes.c_size_t()
        success = self.kernel32.WriteProcessMemory(
            process_handle,
            address,
            data,
            len(data),
            ctypes.byref(written)
        )
        
        if success and written.value == len(data):
            print(f"[+] Written {len(data)} bytes to 0x{address:x}")
            return True
        else:
            print(f"[-] Failed to write remote memory")
            return False
    
    def create_remote_thread(self, process_handle, start_address, parameter=None):
        """Create remote thread in target process"""
        thread_id = wintypes.DWORD()
        thread_handle = self.kernel32.CreateRemoteThread(
            process_handle,
            None,
            0,
            start_address,
            parameter,
            0,
            ctypes.byref(thread_id)
        )
        
        if thread_handle:
            print(f"[+] Created remote thread with ID: {thread_id.value}")
            return thread_handle
        else:
            print(f"[-] Failed to create remote thread")
            return None
    
    def inject_shellcode(self, process_handle, shellcode):
        """Inject and execute shellcode in remote process"""
        # Allocate memory for shellcode
        shellcode_size = len(shellcode)
        remote_memory = self.allocate_remote_memory(process_handle, shellcode_size)
        
        if not remote_memory:
            return False
        
        # Write shellcode
        if not self.write_remote_memory(process_handle, remote_memory, shellcode):
            return False
        
        # Execute shellcode
        thread_handle = self.create_remote_thread(process_handle, remote_memory)
        return thread_handle is not None

class FunctionHook:
    def __init__(self, instrumentation):
        self.instrumentation = instrumentation
        self.hooks = {}
        
    def create_trampoline_x64(self, original_address, hook_function, trampoline_size=14):
        """Create trampoline for x64 function hooking"""
        # This is a simplified trampoline - real implementation would be more complex
        trampoline = bytearray()
        
        # Save registers (simplified)
        trampoline.extend(b"\x50")  # PUSH RAX
        trampoline.extend(b"\x51")  # PUSH RCX
        trampoline.extend(b"\x52")  # PUSH RDX
        
        # Call hook function
        trampoline.extend(b"\x48\xB8")  # MOV RAX, hook_function
        trampoline.extend(struct.pack("<Q", hook_function))
        trampoline.extend(b"\xFF\xD0")  # CALL RAX
        
        # Restore registers
        trampoline.extend(b"\x5A")  # POP RDX
        trampoline.extend(b"\x59")  # POP RCX
        trampoline.extend(b"\x58")  # POP RAX
        
        # Original instructions (would need disassembly in real implementation)
        trampoline.extend(b"\x90" * 8)  # NOPs as placeholder
        
        # Jump back to original function
        return_address = original_address + trampoline_size
        trampoline.extend(b"\xE9")  # JMP
        trampoline.extend(struct.pack("<i", return_address - (original_address + len(trampoline) + 5)))
        
        return bytes(trampoline)
    
    def install_hook(self, process_handle, module_name, function_name, hook_callback):
        """Install function hook (conceptual implementation)"""
        print(f"[*] Installing hook for {function_name} in {module_name}")
        
        # In real implementation, you would:
        # 1. Find function address
        # 2. Create trampoline
        # 3. Patch function prologue
        # 4. Handle relocation
        
        # This is a simplified demonstration
        hook_id = f"{module_name}.{function_name}"
        self.hooks[hook_id] = {
            'original_address': 0x12345678,  # Would be real address
            'trampoline_address': 0x87654321,  # Would be allocated memory
            'hook_function': hook_callback
        }
        
        print(f"[+] Hook installed for {function_name}")
        return True

class ProcessMonitor:
    def __init__(self, instrumentation):
        self.instrumentation = instrumentation
        self.monitored_processes = {}
        
    def start_api_monitoring(self, process_handle):
        """Start monitoring API calls (conceptual)"""
        print("[*] Starting API call monitoring")
        
        # In real implementation, you would:
        # - Set breakpoints on API functions
        # - Use debugging APIs
        # - Implement VEH for exception handling
        
        def api_callback(function_name, parameters):
            print(f"[API] {function_name} called with params: {parameters}")
        
        # Simulate monitoring
        monitor_thread = threading.Thread(target=self._monitor_loop, args=(process_handle, api_callback))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return True
    
    def _monitor_loop(self, process_handle, callback):
        """Monitoring loop (simulated)"""
        while True:
            time.sleep(1)
            # Simulate API calls
            simulated_apis = [
                ("CreateFileW", ["C:\\test.txt", "GENERIC_READ", "OPEN_EXISTING"]),
                ("ReadFile", ["0x1234", "0x2000", "512"]),
                ("RegOpenKeyEx", ["HKEY_LOCAL_MACHINE", "SOFTWARE\\Test"]),
            ]
            
            for api_name, params in simulated_apis:
                callback(api_name, params)

class BinaryInstrumentationToolkit:
    def __init__(self):
        if platform.system() == "Windows":
            self.instrumentation = WindowsInstrumentation()
        else:
            self.instrumentation = LinuxInstrumentation()
        
        self.hook_manager = FunctionHook(self.instrumentation)
        self.monitor = ProcessMonitor(self.instrumentation)
        
    def demonstrate_injection(self, pid):
        """Demonstrate code injection techniques"""
        print(f"[*] Demonstrating code injection on PID: {pid}")
        
        process_handle = self.instrumentation.attach_process(pid=pid)
        if not process_handle:
            return False
        
        # Example: Simple message box shellcode (Windows)
        if platform.system() == "Windows":
            # This is simplified shellcode - real implementation would be proper shellcode
            shellcode = (
                b"\x48\x83\xEC\x28"              # sub rsp, 0x28
                b"\x48\x31\xC9"                  # xor rcx, rcx
                b"\x48\xB9" + b"Test\x00\x00\x00\x00"  # mov rcx, "Test"
                b"\x48\x31\xD2"                  # xor rdx, rdx
                b"\x48\xBA" + b"Hello\x00\x00\x00"    # mov rdx, "Hello"
                b"\x48\xB8" + struct.pack("<Q", 0x12345678)  # mov rax, MessageBoxA address
                b"\xFF\xD0"                      # call rax
                b"\x48\x83\xC4\x28"              # add rsp, 0x28
                b"\xC3"                          # ret
            )
            
            success = self.instrumentation.inject_shellcode(process_handle, shellcode)
            if success:
                print("[+] Shellcode injection successful")
            else:
                print("[-] Shellcode injection failed")
        
        return True
    
    def demonstrate_hooking(self, pid):
        """Demonstrate function hooking"""
        print(f"[*] Demonstrating function hooking on PID: {pid}")
        
        process_handle = self.instrumentation.attach_process(pid=pid)
        if not process_handle:
            return False
        
        # Enumerate modules
        modules = self.instrumentation.enumerate_modules(process_handle)
        print("[+] Loaded modules:")
        for module in modules[:5]:  # Show first 5
            print(f"    - {module['name']} at 0x{module['base_address']:x}")
        
        # Install example hook
        def sample_hook(params):
            print(f"[HOOK] Intercepted call with: {params}")
            return 0
        
        self.hook_manager.install_hook(process_handle, "kernel32.dll", "CreateFileA", sample_hook)
        
        return True
    
    def demonstrate_monitoring(self, pid):
        """Demonstrate process monitoring"""
        print(f"[*] Demonstrating process monitoring on PID: {pid}")
        
        process_handle = self.instrumentation.attach_process(pid=pid)
        if not process_handle:
            return False
        
        self.monitor.start_api_monitoring(process_handle)
        print("[+] API monitoring started (simulated)")
        
        return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 binary_instrumentation.py <PID> [command]")
        print("Commands: inject, hook, monitor, all")
        return
    
    pid = int(sys.argv[1])
    command = sys.argv[2] if len(sys.argv) > 2 else "all"
    
    toolkit = BinaryInstrumentationToolkit()
    
    if command == "inject" or command == "all":
        toolkit.demonstrate_injection(pid)
    
    if command == "hook" or command == "all":
        toolkit.demonstrate_hooking(pid)
    
    if command == "monitor" or command == "all":
        toolkit.demonstrate_monitoring(pid)

if __name__ == "__main__":
    main()
