#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define CHUNK_SIZE 8192

double calculate_file_entropy(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return 0.0;
    }
    
    long byte_counts[256] = {0};
    long total_bytes = 0;
    unsigned char buffer[CHUNK_SIZE];
    size_t bytes_read;
    
    // Count byte frequencies
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            byte_counts[buffer[i]]++;
        }
        total_bytes += bytes_read;
    }
    
    fclose(file);
    
    if (total_bytes == 0) {
        return 0.0;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > 0) {
            double probability = (double)byte_counts[i] / total_bytes;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

// Python C extension wrapper
#include <Python.h>

static PyObject* entropy_calculate_file_entropy(PyObject* self, PyObject* args) {
    const char* filename;
    
    if (!PyArg_ParseTuple(args, "s", &filename)) {
        return NULL;
    }
    
    double entropy = calculate_file_entropy(filename);
    return PyFloat_FromDouble(entropy);
}

static PyMethodDef EntropyMethods[] = {
    {"calculate_file_entropy", entropy_calculate_file_entropy, METH_VARARGS,
     "Calculate file entropy quickly"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef entropyfastmodule = {
    PyModuleDef_HEAD_INIT,
    "entropy_fast",
    "Fast entropy calculation in C",
    -1,
    EntropyMethods
};

PyMODINIT_FUNC PyInit_entropy_fast(void) {
    return PyModule_Create(&entropyfastmodule);
}
