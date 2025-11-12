#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define STRING_TERMINATOR "###END###"
#define MAX_DATA_SIZE 10000

typedef struct {
    unsigned char red;
    unsigned char green;
    unsigned char blue;
} Pixel;

typedef struct {
    char type[3];
    int width;
    int height;
    int max_value;
    Pixel **pixels;
} PPMImage;

// Utility functions
void text_to_binary(const char *text, char *binary) {
    int i, j;
    char *ptr = binary;
    
    for (i = 0; text[i] != '\0'; i++) {
        unsigned char ch = text[i];
        for (j = 7; j >= 0; j--) {
            *ptr++ = ((ch >> j) & 1) ? '1' : '0';
        }
    }
    *ptr = '\0';
}

void binary_to_text(const char *binary, char *text) {
    int i, j = 0;
    char byte[9];
    
    for (i = 0; binary[i] != '\0'; i += 8) {
        if (i + 8 <= strlen(binary)) {
            strncpy(byte, &binary[i], 8);
            byte[8] = '\0';
            text[j++] = (char)strtol(byte, NULL, 2);
        }
    }
    text[j] = '\0';
}

// PPM Image functions
PPMImage* read_ppm(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    PPMImage *image = (PPMImage*)malloc(sizeof(PPMImage));
    fscanf(file, "%2s", image->type);
    fscanf(file, "%d %d", &image->width, &image->height);
    fscanf(file, "%d", &image->max_value);
    fgetc(file); // Skip newline
    
    // Allocate memory for pixels
    image->pixels = (Pixel**)malloc(image->height * sizeof(Pixel*));
    for (int i = 0; i < image->height; i++) {
        image->pixels[i] = (Pixel*)malloc(image->width * sizeof(Pixel));
    }
    
    // Read pixel data
    for (int i = 0; i < image->height; i++) {
        for (int j = 0; j < image->width; j++) {
            image->pixels[i][j].red = fgetc(file);
            image->pixels[i][j].green = fgetc(file);
            image->pixels[i][j].blue = fgetc(file);
        }
    }
    
    fclose(file);
    return image;
}

int write_ppm(const char *filename, PPMImage *image) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("Error: Cannot create file %s\n", filename);
        return 0;
    }
    
    fprintf(file, "%s\n", image->type);
    fprintf(file, "%d %d\n", image->width, image->height);
    fprintf(file, "%d\n", image->max_value);
    
    for (int i = 0; i < image->height; i++) {
        for (int j = 0; j < image->width; j++) {
            fputc(image->pixels[i][j].red, file);
            fputc(image->pixels[i][j].green, file);
            fputc(image->pixels[i][j].blue, file);
        }
    }
    
    fclose(file);
    return 1;
}

void free_ppm(PPMImage *image) {
    for (int i = 0; i < image->height; i++) {
        free(image->pixels[i]);
    }
    free(image->pixels);
    free(image);
}

// Steganography functions
int encode_ppm(PPMImage *image, const char *secret_data) {
    char binary_data[MAX_DATA_SIZE];
    char full_data[1024];
    
    // Prepare data with terminator
    snprintf(full_data, sizeof(full_data), "%s%s", secret_data, STRING_TERMINATOR);
    text_to_binary(full_data, binary_data);
    
    int data_len = strlen(binary_data);
    int max_capacity = image->width * image->height * 3;
    
    if (data_len > max_capacity) {
        printf("Error: Image too small to hold data\n");
        return 0;
    }
    
    int data_index = 0;
    
    // Encode data using LSB
    for (int i = 0; i < image->height && data_index < data_len; i++) {
        for (int j = 0; j < image->width && data_index < data_len; j++) {
            // Encode in red channel
            if (data_index < data_len) {
                image->pixels[i][j].red = (image->pixels[i][j].red & 0xFE) | (binary_data[data_index] - '0');
                data_index++;
            }
            
            // Encode in green channel
            if (data_index < data_len) {
                image->pixels[i][j].green = (image->pixels[i][j].green & 0xFE) | (binary_data[data_index] - '0');
                data_index++;
            }
            
            // Encode in blue channel
            if (data_index < data_len) {
                image->pixels[i][j].blue = (image->pixels[i][j].blue & 0xFE) | (binary_data[data_index] - '0');
                data_index++;
            }
        }
    }
    
    printf("Data encoded successfully\n");
    return 1;
}

char* decode_ppm(PPMImage *image) {
    int max_bits = image->width * image->height * 3;
    char *binary_data = (char*)malloc(max_bits + 1);
    int bit_index = 0;
    
    // Extract LSB from each pixel
    for (int i = 0; i < image->height; i++) {
        for (int j = 0; j < image->width; j++) {
            binary_data[bit_index++] = (image->pixels[i][j].red & 1) ? '1' : '0';
            binary_data[bit_index++] = (image->pixels[i][j].green & 1) ? '1' : '0';
            binary_data[bit_index++] = (image->pixels[i][j].blue & 1) ? '1' : '0';
        }
    }
    binary_data[bit_index] = '\0';
    
    // Convert to text
    char *text = (char*)malloc(bit_index / 8 + 1);
    binary_to_text(binary_data, text);
    
    free(binary_data);
    
    // Check for terminator
    char *terminator_pos = strstr(text, STRING_TERMINATOR);
    if (terminator_pos) {
        *terminator_pos = '\0';
        return text;
    }
    
    free(text);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage:\n");
        printf("  Encode: %s encode input.ppm output.ppm \"secret data\"\n", argv[0]);
        printf("  Decode: %s decode input.ppm\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "encode") == 0) {
        PPMImage *image = read_ppm(argv[2]);
        if (!image) return 1;
        
        if (encode_ppm(image, argv[4])) {
            write_ppm(argv[3], image);
        }
        
        free_ppm(image);
    }
    else if (strcmp(argv[1], "decode") == 0) {
        PPMImage *image = read_ppm(argv[2]);
        if (!image) return 1;
        
        char *decoded = decode_ppm(image);
        if (decoded) {
            printf("Decoded data: %s\n", decoded);
            free(decoded);
        } else {
            printf("No hidden data found\n");
        }
        
        free_ppm(image);
    }
    
    return 0;
}
