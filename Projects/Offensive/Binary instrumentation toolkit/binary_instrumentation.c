#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#define JMP_OPCODE 0xE9
#define NOP_OPCODE 0x90

typedef struct _HOOK_INFO {
    LPVOID original_function;
    LPVOID hook_function;
    LPVOID trampoline;
    BYTE original_bytes[20];
    BYTE hook_bytes[20];
    DWORD hook_size;
} HOOK_INFO, *PHOOK_INFO;

class BinaryInstrumentation {
private:
    HOOK_INFO hooks[100];
    int hook_count;

public:
    BinaryInstrumentation() : hook_count(0) {
        memset(hooks, 0, sizeof(hooks));
    }

    // Process manipulation functions
    HANDLE AttachToProcess(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess == NULL) {
            printf("[-] Failed to open process: %lu\n", GetLastError());
            return NULL;
        }
        printf("[+] Attached to process PID: %lu\n", pid);
        return hProcess;
    }

    LPVOID InjectShellcode(HANDLE hProcess, const BYTE* shellcode, SIZE_T shellcode_size) {
        // Allocate memory in target process
        LPVOID remote_memory = VirtualAllocEx(hProcess, NULL, shellcode_size, 
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remote_memory == NULL) {
            printf("[-] Failed to allocate remote memory: %lu\n", GetLastError());
            return NULL;
        }

        // Write shellcode to remote process
        SIZE_T bytes_written;
        if (!WriteProcessMemory(hProcess, remote_memory, shellcode, shellcode_size, &bytes_written)) {
            printf("[-] Failed to write shellcode: %lu\n", GetLastError());
            VirtualFreeEx(hProcess, remote_memory, 0, MEM_RELEASE);
            return NULL;
        }

        printf("[+] Injected %zu bytes at 0x%p\n", bytes_written, remote_memory);
        return remote_memory;
    }

    BOOL ExecuteRemoteCode(HANDLE hProcess, LPVOID remote_address) {
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                          (LPTHREAD_START_ROUTINE)remote_address, NULL, 0, NULL);
        if (hThread == NULL) {
            printf("[-] Failed to create remote thread: %lu\n", GetLastError());
            return FALSE;
        }

        printf("[+] Created remote thread: %lu\n", GetThreadId(hThread));
        CloseHandle(hThread);
        return TRUE;
    }

    // Function hooking implementation
    BOOL InstallHook(LPVOID target_function, LPVOID hook_function) {
        if (hook_count >= 100) {
            printf("[-] Maximum hook count reached\n");
            return FALSE;
        }

        PHOOK_INFO hook = &hooks[hook_count];
        hook->original_function = target_function;
        hook->hook_function = hook_function;

        // Save original bytes
        memcpy(hook->original_bytes, target_function, sizeof(hook->original_bytes));

        // Calculate relative jump offset
        DWORD_PTR jump_offset = (DWORD_PTR)hook_function - (DWORD_PTR)target_function - 5;

        // Create hook bytes: JMP hook_function
        hook->hook_bytes[0] = JMP_OPCODE;
        *(DWORD*)(hook->hook_bytes + 1) = (DWORD)jump_offset;

        // Change page protection
        DWORD old_protect;
        if (!VirtualProtect(target_function, 5, PAGE_EXECUTE_READWRITE, &old_protect)) {
            printf("[-] Failed to change page protection: %lu\n", GetLastError());
            return FALSE;
        }

        // Install hook
        memcpy(target_function, hook->hook_bytes, 5);

        // Restore protection
        VirtualProtect(target_function, 5, old_protect, &old_protect);

        printf("[+] Hook installed: 0x%p -> 0x%p\n", target_function, hook_function);
        hook_count++;

        return TRUE;
    }

    BOOL RemoveHook(LPVOID target_function) {
        for (int i = 0; i < hook_count; i++) {
            if (hooks[i].original_function == target_function) {
                DWORD old_protect;
                VirtualProtect(target_function, 5, PAGE_EXECUTE_READWRITE, &old_protect);
                
                // Restore original bytes
                memcpy(target_function, hooks[i].original_bytes, 5);
                
                VirtualProtect(target_function, 5, old_protect, &old_protect);
                
                printf("[+] Hook removed: 0x%p\n", target_function);
                return TRUE;
            }
        }
        return FALSE;
    }

    // Memory patching functions
    BOOL PatchMemory(HANDLE hProcess, LPVOID address, const BYTE* patch, SIZE_T patch_size) {
        DWORD old_protect;
        if (!VirtualProtectEx(hProcess, address, patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            printf("[-] Failed to change memory protection: %lu\n", GetLastError());
            return FALSE;
        }

        SIZE_T bytes_written;
        if (!WriteProcessMemory(hProcess, address, patch, patch_size, &bytes_written)) {
            printf("[-] Failed to patch memory: %lu\n", GetLastError());
            return FALSE;
        }

        VirtualProtectEx(hProcess, address, patch_size, old_protect, &old_protect);
        printf("[+] Patched %zu bytes at 0x%p\n", bytes_written, address);
        return TRUE;
    }

    // Process enumeration
    void ListProcesses() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to create process snapshot: %lu\n", GetLastError());
            return;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            printf("\n=== RUNNING PROCESSES ===\n");
            do {
                printf("PID: %6lu | %s\n", pe.th32ProcessID, pe.szExeFile);
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }

    // Module enumeration
    void ListModules(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess == NULL) {
            printf("[-] Failed to open process: %lu\n", GetLastError());
            return;
        }

        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
            printf("\n=== LOADED MODULES (PID: %lu) ===\n", pid);
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char moduleName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hModules[i], moduleName, sizeof(moduleName))) {
                    printf("0x%p | %s\n", hModules[i], moduleName);
                }
            }
        }

        CloseHandle(hProcess);
    }
};

// Example hook function
void __declspec(naked) ExampleHook() {
    __asm {
        pushad
        // Custom code here
        printf("[HOOK] Function intercepted!\n");
        popad
        // Continue to original function
        jmp [original_function]
    }
}

void DemonstrateInjection() {
    printf("\n=== CODE INJECTION DEMONSTRATION ===\n");
    
    BinaryInstrumentation inst;
    
    // Get current process for demonstration
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = inst.AttachToProcess(pid);
    
    if (hProcess) {
        // Simple shellcode that does nothing (NOP sled)
        BYTE shellcode[] = { 0x90, 0x90, 0x90, 0x90, 0xC3 }; // NOP, NOP, NOP, NOP, RET
        
        LPVOID remote_mem = inst.InjectShellcode(hProcess, shellcode, sizeof(shellcode));
        if (remote_mem) {
            inst.ExecuteRemoteCode(hProcess, remote_mem);
            VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        }
        
        CloseHandle(hProcess);
    }
}

void DemonstrateHooking() {
    printf("\n=== FUNCTION HOOKING DEMONSTRATION ===\n");
    
    BinaryInstrumentation inst;
    
    // Hook MessageBoxA for demonstration
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) {
        FARPROC messageBoxAddr = GetProcAddress(hUser32, "MessageBoxA");
        if (messageBoxAddr) {
            printf("[*] MessageBoxA address: 0x%p\n", messageBoxAddr);
            // Note: In real usage, you'd provide a proper hook function
            // inst.InstallHook(messageBoxAddr, (LPVOID)ExampleHook);
        }
        FreeLibrary(hUser32);
    }
}

void DemonstrateProcessEnumeration() {
    printf("\n=== PROCESS ENUMERATION ===\n");
    
    BinaryInstrumentation inst;
    inst.ListProcesses();
    
    // Show modules for current process
    inst.ListModules(GetCurrentProcessId());
}

int main() {
    printf("Binary Instrumentation Toolkit\n");
    printf("==============================\n");
    printf("FOR AUTHORIZED SECURITY RESEARCH ONLY\n\n");
    
    DemonstrateProcessEnumeration();
    DemonstrateInjection();
    DemonstrateHooking();
    
    printf("\n=== LEGAL NOTICE ===\n");
    printf("This tool is for:\n");
    printf("  ✅ Authorized penetration testing\n");
    printf("  ✅ Malware analysis\n");
    printf("  ✅ Security research\n");
    printf("  ✅ Educational purposes\n");
    printf("\nProhibited uses:\n");
    printf("  ❌ Unauthorized system modification\n");
    printf("  ❌ Malicious code injection\n");
    printf("  ❌ Attacks without permission\n");
    
    return 0;
}
