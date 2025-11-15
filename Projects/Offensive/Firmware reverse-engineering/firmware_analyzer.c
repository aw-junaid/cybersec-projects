#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#define MAX_STRING_LENGTH 256
#define BUFFER_SIZE 4096
#define MAX_STRINGS 10000

typedef struct {
    unsigned char *data;
    size_t size;
    char *filename;
} Firmware;

typedef struct {
    char **strings;
    int count;
    int capacity;
} StringList;

typedef struct {
    char *vulnerability;
    char *description;
    int severity; // 1-10 scale
} Vulnerability;

// Basic firmware analysis functions
Firmware* load_firmware(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open firmware file %s\n", filename);
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0) {
        printf("Error: Invalid file size\n");
        fclose(file);
        return NULL;
    }
    
    // Allocate memory for firmware
    Firmware *fw = malloc(sizeof(Firmware));
    if (!fw) {
        printf("Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    
    fw->data = malloc(file_size);
    if (!fw->data) {
        printf("Error: Memory allocation failed\n");
        free(fw);
        fclose(file);
        return NULL;
    }
    
    // Read file data
    size_t bytes_read = fread(fw->data, 1, file_size, file);
    fclose(file);
    
    if (bytes_read != file_size) {
        printf("Error: File read incomplete\n");
        free(fw->data);
        free(fw);
        return NULL;
    }
    
    fw->size = file_size;
    fw->filename = strdup(filename);
    
    printf("Loaded firmware: %s (%zu bytes)\n", filename, file_size);
    return fw;
}

void free_firmware(Firmware *fw) {
    if (fw) {
        free(fw->data);
        free(fw->filename);
        free(fw);
    }
}

// String extraction functions
int is_printable_ascii(unsigned char c) {
    return (c >= 32 && c <= 126);
}

StringList* extract_strings(Firmware *fw, int min_length) {
    StringList *list = malloc(sizeof(StringList));
    if (!list) return NULL;
    
    list->capacity = MAX_STRINGS;
    list->count = 0;
    list->strings = malloc(sizeof(char*) * list->capacity);
    
    char current_string[MAX_STRING_LENGTH];
    int string_index = 0;
    
    for (size_t i = 0; i < fw->size; i++) {
        unsigned char c = fw->data[i];
        
        if (is_printable_ascii(c)) {
            if (string_index < MAX_STRING_LENGTH - 1) {
                current_string[string_index++] = c;
            }
        } else {
            if (string_index >= min_length) {
                current_string[string_index] = '\0';
                
                // Add to list
                if (list->count < list->capacity) {
                    list->strings[list->count] = strdup(current_string);
                    list->count++;
                }
            }
            string_index = 0;
        }
    }
    
    // Handle last string if file doesn't end with non-printable
    if (string_index >= min_length) {
        current_string[string_index] = '\0';
        if (list->count < list->capacity) {
            list->strings[list->count] = strdup(current_string);
            list->count++;
        }
    }
    
    printf("Extracted %d strings\n", list->count);
    return list;
}

void free_string_list(StringList *list) {
    if (list) {
        for (int i = 0; i < list->count; i++) {
            free(list->strings[i]);
        }
        free(list->strings);
        free(list);
    }
}

// Pattern matching for vulnerability detection
int search_pattern(Firmware *fw, const unsigned char *pattern, size_t pattern_len) {
    int matches = 0;
    
    for (size_t i = 0; i <= fw->size - pattern_len; i++) {
        if (memcmp(&fw->data[i], pattern, pattern_len) == 0) {
            matches++;
        }
    }
    
    return matches;
}

// Check for common dangerous functions
void check_dangerous_functions(Firmware *fw) {
    struct {
        const char *name;
        const char *risk;
    } dangerous_funcs[] = {
        {"strcpy", "Buffer overflow risk"},
        {"gets", "Extremely dangerous - no bounds checking"},
        {"sprintf", "Buffer overflow risk"},
        {"strcat", "Buffer overflow risk"},
        {"system", "Command injection risk"},
        {"popen", "Command injection risk"},
        {NULL, NULL}
    };
    
    printf("\nDangerous Function Analysis:\n");
    
    for (int i = 0; dangerous_funcs[i].name != NULL; i++) {
        int matches = search_pattern(fw, (unsigned char*)dangerous_funcs[i].name, 
                                   strlen(dangerous_funcs[i].name));
        if (matches > 0) {
            printf("  [WARNING] %s: %s (%d occurrences)\n", 
                   dangerous_funcs[i].name, dangerous_funcs[i].risk, matches);
        }
    }
}

// Check for hardcoded credentials
void check_hardcoded_credentials(StringList *strings) {
    const char *common_passwords[] = {
        "admin", "password", "1234", "default", "root", 
        "pass", "pwd", "123456", "guest", NULL
    };
    
    printf("\nHardcoded Credentials Check:\n");
    
    for (int i = 0; common_passwords[i] != NULL; i++) {
        for (int j = 0; j < strings->count; j++) {
            if (strcmp(strings->strings[j], common_passwords[i]) == 0) {
                printf("  [WARNING] Found default password: %s\n", common_passwords[i]);
                break;
            }
        }
    }
}

// File type identification
void identify_file_type(Firmware *fw) {
    struct {
        const unsigned char *magic;
        size_t length;
        const char *description;
    } magic_numbers[] = {
        {(unsigned char*)"\x7f""ELF", 4, "ELF Executable"},
        {(unsigned char*)"MZ", 2, "Windows PE Executable"},
        {(unsigned char*)"\x1f\x8b", 2, "GZIP Compressed"},
        {(unsigned char*)"\x42\x5a\x68", 3, "BZIP2 Compressed"},
        {(unsigned char*)"\xfd""7zXZ", 6, "XZ Compressed"},
        {(unsigned char*)"\x55\xaa", 2, "MBR Bootloader"},
        {NULL, 0, NULL}
    };
    
    printf("\nFile Type Identification:\n");
    
    for (int i = 0; magic_numbers[i].magic != NULL; i++) {
        if (fw->size >= magic_numbers[i].length) {
            if (memcmp(fw->data, magic_numbers[i].magic, magic_numbers[i].length) == 0) {
                printf("  File Type: %s\n", magic_numbers[i].description);
                return;
            }
        }
    }
    
    printf("  File Type: Unknown\n");
}

// Generate hex dump
void generate_hex_dump(Firmware *fw, size_t offset, size_t length) {
    if (offset >= fw->size) return;
    
    if (offset + length > fw->size) {
        length = fw->size - offset;
    }
    
    printf("\nHex Dump (offset: 0x%zx, length: %zu):\n", offset, length);
    printf("Offset    Hexadecimal                           ASCII\n");
    printf("--------  ------------------------------------  ----------------\n");
    
    for (size_t i = 0; i < length; i += 16) {
        printf("%08zx  ", offset + i);
        
        // Hexadecimal portion
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                printf("%02x ", fw->data[offset + i + j]);
            } else {
                printf("   ");
            }
            
            if (j == 7) printf(" ");
        }
        
        printf(" ");
        
        // ASCII portion
        for (size_t j = 0; j < 16; j++) {
            if (i + j < length) {
                unsigned char c = fw->data[offset + i + j];
                printf("%c", is_printable_ascii(c) ? c : '.');
            } else {
                printf(" ");
            }
        }
        
        printf("\n");
    }
}

// Main analysis function
void analyze_firmware(Firmware *fw) {
    printf("\n=== Firmware Security Analysis ===\n");
    
    // File type identification
    identify_file_type(fw);
    
    // Extract and analyze strings
    StringList *strings = extract_strings(fw, 4);
    
    // Check for dangerous functions
    check_dangerous_functions(fw);
    
    // Check for hardcoded credentials
    check_hardcoded_credentials(strings);
    
    // Generate sample hex dump
    generate_hex_dump(fw, 0, 256);
    
    // Show some interesting strings
    printf("\nInteresting Strings Found (first 20):\n");
    int shown = 0;
    for (int i = 0; i < strings->count && shown < 20; i++) {
        // Show strings that might be interesting
        if (strlen(strings->strings[i]) > 8) {
            printf("  %s\n", strings->strings[i]);
            shown++;
        }
    }
    
    free_string_list(strings);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <firmware_file>\n", argv[0]);
        return 1;
    }
    
    printf("Firmware Reverse Engineering Tool\n");
    printf("==================================\n");
    
    // Load firmware
    Firmware *fw = load_firmware(argv[1]);
    if (!fw) {
        return 1;
    }
    
    // Perform analysis
    analyze_firmware(fw);
    
    // Cleanup
    free_firmware(fw);
    
    return 0;
}
