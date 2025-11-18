#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)

// PE file structures
typedef struct {
    uint16_t e_magic;      // Magic number
    uint16_t e_cblp;       // Bytes on last page of file
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;    // OEM information; e_oemid specific
    uint16_t e_res2[10];   // Reserved words
    uint32_t e_lfanew;     // File address of new exe header
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

typedef struct {
    char name[9];
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t characteristics;
    double entropy;
} SectionInfo;

typedef struct {
    char filename[256];
    uint32_t file_size;
    uint16_t machine_type;
    uint16_t number_of_sections;
    uint32_t entry_point;
    SectionInfo* sections;
} PEAnalysis;

// Function prototypes
int parse_pe_file(const char* filename, PEAnalysis* analysis);
void print_pe_analysis(const PEAnalysis* analysis);
double calculate_entropy(uint8_t* data, size_t size);
void free_pe_analysis(PEAnalysis* analysis);

int parse_pe_file(const char* filename, PEAnalysis* analysis) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return -1;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    analysis->file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    strncpy(analysis->filename, filename, sizeof(analysis->filename) - 1);

    // Read DOS header
    IMAGE_DOS_HEADER dos_header;
    if (fread(&dos_header, sizeof(dos_header), 1, file) != 1) {
        printf("Error: Cannot read DOS header\n");
        fclose(file);
        return -1;
    }

    // Check DOS signature
    if (dos_header.e_magic != 0x5A4D) { // "MZ"
        printf("Error: Not a valid PE file (missing MZ signature)\n");
        fclose(file);
        return -1;
    }

    // Seek to PE header
    fseek(file, dos_header.e_lfanew, SEEK_SET);

    // Read PE signature
    uint32_t pe_signature;
    if (fread(&pe_signature, sizeof(pe_signature), 1, file) != 1) {
        printf("Error: Cannot read PE signature\n");
        fclose(file);
        return -1;
    }

    if (pe_signature != 0x00004550) { // "PE\0\0"
        printf("Error: Not a valid PE file (missing PE signature)\n");
        fclose(file);
        return -1;
    }

    // Read file header
    IMAGE_FILE_HEADER file_header;
    if (fread(&file_header, sizeof(file_header), 1, file) != 1) {
        printf("Error: Cannot read file header\n");
        fclose(file);
        return -1;
    }

    analysis->machine_type = file_header.Machine;
    analysis->number_of_sections = file_header.NumberOfSections;

    // Skip optional header for simplicity
    fseek(file, file_header.SizeOfOptionalHeader, SEEK_CUR);

    // Read section headers
    analysis->sections = malloc(file_header.NumberOfSections * sizeof(SectionInfo));
    if (!analysis->sections) {
        printf("Error: Memory allocation failed\n");
        fclose(file);
        return -1;
    }

    IMAGE_SECTION_HEADER section_header;
    for (int i = 0; i < file_header.NumberOfSections; i++) {
        if (fread(&section_header, sizeof(section_header), 1, file) != 1) {
            printf("Error: Cannot read section header %d\n", i);
            free(analysis->sections);
            fclose(file);
            return -1;
        }

        SectionInfo* section = &analysis->sections[i];
        memcpy(section->name, section_header.Name, 8);
        section->name[8] = '\0';
        section->virtual_address = section_header.VirtualAddress;
        section->raw_size = section_header.SizeOfRawData;
        section->characteristics = section_header.Characteristics;

        // Calculate entropy for the section
        if (section_header.SizeOfRawData > 0 && section_header.PointerToRawData > 0) {
            uint8_t* section_data = malloc(section_header.SizeOfRawData);
            if (section_data) {
                long current_pos = ftell(file);
                fseek(file, section_header.PointerToRawData, SEEK_SET);
                fread(section_data, 1, section_header.SizeOfRawData, file);
                fseek(file, current_pos, SEEK_SET);

                section->entropy = calculate_entropy(section_data, section_header.SizeOfRawData);
                free(section_data);
            }
        } else {
            section->entropy = 0.0;
        }
    }

    fclose(file);
    return 0;
}

double calculate_entropy(uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    int frequency[256] = {0};
    
    // Calculate byte frequencies
    for (size_t i = 0; i < size; i++) {
        frequency[data[i]]++;
    }

    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double probability = (double)frequency[i] / size;
            entropy -= probability * (probability > 0 ? __builtin_log2(probability) : 0);
        }
    }

    return entropy;
}

void print_pe_analysis(const PEAnalysis* analysis) {
    printf("PE File Analysis Report\n");
    printf("======================\n");
    printf("Filename: %s\n", analysis->filename);
    printf("File size: %u bytes\n", analysis->file_size);
    printf("Machine type: 0x%04X\n", analysis->machine_type);
    printf("Number of sections: %u\n", analysis->number_of_sections);
    printf("\nSection Analysis:\n");
    printf("%-12s %-10s %-10s %-12s %s\n", 
           "Name", "VAddr", "RawSize", "Chars", "Entropy");
    printf("%-12s %-10s %-10s %-12s %s\n", 
           "----", "-----", "-------", "-----", "-------");

    for (unsigned int i = 0; i < analysis->number_of_sections; i++) {
        const SectionInfo* section = &analysis->sections[i];
        printf("%-12s 0x%08X 0x%08X 0x%08X %.2f\n",
               section->name,
               section->virtual_address,
               section->raw_size,
               section->characteristics,
               section->entropy);
    }

    // Packing detection based on entropy
    int high_entropy_sections = 0;
    for (unsigned int i = 0; i < analysis->number_of_sections; i++) {
        if (analysis->sections[i].entropy > 7.0) {
            high_entropy_sections++;
        }
    }

    printf("\nPacking Analysis:\n");
    printf("High entropy sections (>7.0): %d\n", high_entropy_sections);
    if (high_entropy_sections > 1) {
        printf("WARNING: File may be packed or encrypted\n");
    } else {
        printf("File appears to be unpacked\n");
    }
}

void free_pe_analysis(PEAnalysis* analysis) {
    if (analysis->sections) {
        free(analysis->sections);
        analysis->sections = NULL;
    }
}

// Simple string extraction
void extract_strings(const char* filename, int min_length) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* file_data = malloc(file_size);
    if (!file_data) {
        printf("Error: Memory allocation failed\n");
        fclose(file);
        return;
    }

    fread(file_data, 1, file_size, file);
    fclose(file);

    printf("Extracted strings (min length: %d):\n", min_length);
    printf("==================================\n");

    int in_string = 0;
    int string_length = 0;
    char current_string[256] = {0};
    int string_index = 0;

    for (long i = 0; i < file_size; i++) {
        uint8_t byte = file_data[i];
        
        if (byte >= 32 && byte <= 126) { // Printable ASCII
            if (string_index < sizeof(current_string) - 1) {
                current_string[string_index++] = byte;
            }
            in_string = 1;
        } else {
            if (in_string && string_index >= min_length) {
                current_string[string_index] = '\0';
                printf("%s\n", current_string);
            }
            in_string = 0;
            string_index = 0;
        }
    }

    // Handle string at end of file
    if (in_string && string_index >= min_length) {
        current_string[string_index] = '\0';
        printf("%s\n", current_string);
    }

    free(file_data);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pe_file> [--strings]\n", argv[0]);
        printf("       %s <pe_file> --strings [min_length]\n", argv[0]);
        return 1;
    }

    printf("Binary Reverse Engineering Tool - C Implementation\n");
    printf("FOR EDUCATIONAL PURPOSES ONLY\n\n");

    if (argc >= 3 && strcmp(argv[2], "--strings") == 0) {
        int min_length = 4;
        if (argc >= 4) {
            min_length = atoi(argv[3]);
        }
        extract_strings(argv[1], min_length);
        return 0;
    }

    PEAnalysis analysis = {0};
    
    if (parse_pe_file(argv[1], &analysis) == 0) {
        print_pe_analysis(&analysis);
        free_pe_analysis(&analysis);
    } else {
        printf("Failed to analyze PE file\n");
        return 1;
    }

    return 0;
}
