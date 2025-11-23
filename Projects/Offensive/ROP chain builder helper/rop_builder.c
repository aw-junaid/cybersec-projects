#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint64_t address;
    char instructions[256];
    char category[32];
    int length;
} rop_gadget_t;

typedef struct {
    rop_gadget_t* gadgets;
    int count;
    int capacity;
} gadget_list_t;

void init_gadget_list(gadget_list_t* list) {
    list->capacity = 100;
    list->count = 0;
    list->gadgets = malloc(list->capacity * sizeof(rop_gadget_t));
}

void add_gadget(gadget_list_t* list, uint64_t address, const char* instructions, const char* category) {
    if (list->count >= list->capacity) {
        list->capacity *= 2;
        list->gadgets = realloc(list->gadgets, list->capacity * sizeof(rop_gadget_t));
    }
    
    rop_gadget_t* gadget = &list->gadgets[list->count++];
    gadget->address = address;
    strncpy(gadget->instructions, instructions, sizeof(gadget->instructions));
    strncpy(gadget->category, category, sizeof(gadget->category));
    gadget->length = strlen(instructions);
}

void demonstrate_rop_primitives() {
    printf("\n=== ROP PRIMITIVES AND GADGET TYPES ===\n");
    
    printf("\n1. Register Control Gadgets:\n");
    printf("   pop rax    ; ret  - Load value into RAX\n");
    printf("   pop rdi    ; ret  - Set first function argument\n");
    printf("   pop rsi    ; ret  - Set second function argument\n");
    printf("   pop rdx    ; ret  - Set third function argument\n");
    
    printf("\n2. Stack Pivot Gadgets:\n");
    printf("   xchg rsp, rax ; ret  - Exchange stack pointer\n");
    printf("   mov rsp, rbp  ; ret  - Move value into stack pointer\n");
    printf("   add rsp, 0x28 ; ret  - Adjust stack pointer\n");
    
    printf("\n3. Memory Operation Gadgets:\n");
    printf("   mov [rdi], rsi ; ret  - Write to memory\n");
    printf("   mov rax, [rbx] ; ret  - Read from memory\n");
    printf("   lea rax, [rbx+rcx] ; ret - Load effective address\n");
    
    printf("\n4. Arithmetic Gadgets:\n");
    printf("   add rax, rbx ; ret  - Addition\n");
    printf("   sub rax, 0x10 ; ret - Subtraction\n");
    printf("   xor rax, rax ; ret  - Clear register\n");
    
    printf("\n5. System Call Gadgets:\n");
    printf("   syscall       ; ret  - Linux system call\n");
    printf("   int 0x80      ; ret  - Linux 32-bit system call\n");
}

void demonstrate_linux_x64_chain() {
    printf("\n=== LINUX x64 EXECVE ROP CHAIN ===\n");
    
    printf("\nGoal: execve(\"/bin/sh\", NULL, NULL)\n");
    printf("\nChain Structure:\n");
    printf("1. Write \"/bin/sh\" string to writable memory\n");
    printf("2. Set RDI = address of \"/bin/sh\"\n");
    printf("3. Set RSI = 0\n");
    printf("4. Set RDX = 0\n");
    printf("5. Set RAX = 59 (execve syscall number)\n");
    printf("6. SYSCALL\n");
    
    printf("\nExample Gadgets:\n");
    printf("   0x401000: pop rdi ; ret\n");
    printf("   0x401010: pop rsi ; ret\n");
    printf("   0x401020: pop rdx ; ret\n");
    printf("   0x401030: pop rax ; ret\n");
    printf("   0x401040: syscall ; ret\n");
    
    printf("\nFinal Chain:\n");
    printf("   [pop rdi gadget] -> 0x402000 (address of \"/bin/sh\")\n");
    printf("   [pop rsi gadget] -> 0x0\n");
    printf("   [pop rdx gadget] -> 0x0\n");
    printf("   [pop rax gadget] -> 59\n");
    printf("   [syscall gadget]\n");
}

void demonstrate_windows_x64_chain() {
    printf("\n=== WINDOWS x64 ROP CHAIN ===\n");
    
    printf("\nGoal: Call WinExec(\"calc.exe\", SW_SHOW)\n");
    printf("\nChain Structure:\n");
    printf("1. Load library if needed\n");
    printf("2. Get function address\n");
    printf("3. Set RCX = \"calc.exe\" string address\n");
    printf("4. Set RDX = SW_SHOW (5)\n");
    printf("5. Call WinExec\n");
    
    printf("\nRequired Gadgets:\n");
    printf("   - pop rcx ; ret\n");
    printf("   - pop rdx ; ret\n");
    printf("   - Indirect call gadget\n");
}

void generate_rop_chain_example() {
    printf("\n=== GENERATING SAMPLE ROP CHAIN ===\n");
    
    gadget_list_t gadgets;
    init_gadget_list(&gadgets);
    
    // Add sample gadgets
    add_gadget(&gadgets, 0x401000, "pop rdi ; ret", "register_control");
    add_gadget(&gadgets, 0x401010, "pop rsi ; ret", "register_control");
    add_gadget(&gadgets, 0x401020, "pop rdx ; ret", "register_control");
    add_gadget(&gadgets, 0x401030, "pop rax ; ret", "register_control");
    add_gadget(&gadgets, 0x401040, "syscall ; ret", "system_call");
    add_gadget(&gadgets, 0x401050, "mov [rdi], rsi ; ret", "memory_operation");
    
    printf("\nAvailable Gadgets:\n");
    for (int i = 0; i < gadgets.count; i++) {
        printf("   0x%016lx: %-30s [%s]\n", 
               gadgets.gadgets[i].address,
               gadgets.gadgets[i].instructions,
               gadgets.gadgets[i].category);
    }
    
    printf("\nBuilding execve chain:\n");
    printf("   1. 0x401000 (pop rdi) -> 0x402000 (/bin/sh address)\n");
    printf("   2. 0x401010 (pop rsi) -> 0x0\n");
    printf("   3. 0x401020 (pop rdx) -> 0x0\n");
    printf("   4. 0x401030 (pop rax) -> 59\n");
    printf("   5. 0x401040 (syscall)\n");
    
    free(gadgets.gadgets);
}

void show_mitigation_techniques() {
    printf("\n=== ROP MITIGATION TECHNIQUES ===\n");
    
    printf("\n1. Address Space Layout Randomization (ASLR):\n");
    printf("   - Randomizes base addresses of modules\n");
    printf("   - Makes gadget addresses unpredictable\n");
    printf("   - Bypass: Information leaks, brute force\n");
    
    printf("\n2. Data Execution Prevention (DEP):\n");
    printf("   - Prevents code execution from data regions\n");
    printf("   - Forces use of ROP/JOP\n");
    printf("   - Bypass: ROP chains\n");
    
    printf("\n3. Control Flow Guard (CFG):\n");
    printf("   - Validates indirect function calls\n");
    printf("   - Bypass: Non-call gadgets, CFG bypasses\n");
    
    printf("\n4. Stack Canaries:\n");
    printf("   - Detects stack buffer overflows\n");
    printf("   - Bypass: Information leaks, canary prediction\n");
    
    printf("\n5. Return Address Sanitization:\n");
    printf("   - Validates return addresses\n");
    printf("   - Bypass: Complex ROP chains\n");
}

int main() {
    printf("ROP Chain Builder Helper - Educational Tool\n");
    printf("===========================================\n");
    printf("FOR AUTHORIZED SECURITY RESEARCH ONLY\n\n");
    
    demonstrate_rop_primitives();
    demonstrate_linux_x64_chain();
    demonstrate_windows_x64_chain();
    generate_rop_chain_example();
    show_mitigation_techniques();
    
    printf("\n=== LEGAL AND ETHICAL USAGE ===\n");
    printf("This tool is intended for:\n");
    printf("  ✅ Authorized penetration testing\n");
    printf("  ✅ Security research and education\n");
    printf("  ✅ CTF competitions\n");
    printf("  ✅ Vulnerability research\n");
    printf("\nProhibited uses:\n");
    printf("  ❌ Unauthorized system testing\n");
    printf("  ❌ Malicious exploitation\n");
    printf("  ❌ Attacks without permission\n");
    
    return 0;
}
