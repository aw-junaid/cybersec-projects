/* gpu_md5_opencl.c - Educational host program to run md5_kernel.cl
   Compile (Kali):
     sudo apt install -y ocl-icd-opencl-dev
     gcc -o gpu_md5_opencl gpu_md5_opencl.c -lOpenCL

   Usage:
     ./gpu_md5_opencl
   NOTE: candidate list is embedded for demo; replace with your own small list.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <OpenCL/opencl.h> // on some systems: <CL/cl.h>
#include <stdint.h>

// Helper: read kernel file
char* read_file(const char *path, size_t *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz+1);
    fread(buf,1,sz,f);
    buf[sz]=0;
    fclose(f);
    if (outlen) *outlen = sz;
    return buf;
}

/* For brevity: minimal error checks, displays computed digests for demo */
int main() {
    const char *candidates[] = {"password","123456","letmein","secret"};
    const int N = sizeof(candidates)/sizeof(candidates[0]);

    // pad to 64 bytes (MD5 single-block)
    unsigned char *inbuf = calloc(N, 64);
    for (int i=0;i<N;i++) {
        size_t L = strlen(candidates[i]);
        if (L > 55) { printf("Candidate too long\n"); return 1; }
        memcpy(inbuf + i*64, candidates[i], L);
        inbuf[i*64 + L] = 0x80;
        uint32_t bitlen = (uint32_t)(L * 8);
        memcpy(inbuf + i*64 + 56, &bitlen, 4); // little-endian
        // upper length bytes = 0
    }

    // load kernel from file 'md5_kernel.cl'
    size_t kernel_sz;
    char *kernel_src = read_file("md5_kernel.cl", &kernel_sz);
    if (!kernel_src) { printf("Kernel not found\n"); return 1; }

    // OpenCL bootstrap: platform, device, context, queue
    cl_platform_id platform;
    clGetPlatformIDs(1, &platform, NULL);
    cl_device_id device;
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    cl_context ctx = clCreateContext(NULL, 1, &device, NULL, NULL, NULL);
    cl_command_queue q = clCreateCommandQueue(ctx, device, 0, NULL);

    cl_int err;
    cl_program prog = clCreateProgramWithSource(ctx, 1, (const char**)&kernel_src, NULL, &err);
    err = clBuildProgram(prog, 1, &device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        // print build log
        size_t loglen;
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &loglen);
        char *log = malloc(loglen+1);
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, loglen, log, NULL);
        log[loglen]=0;
        printf("BUILD LOG:\n%s\n", log);
        free(log);
        return 1;
    }
    cl_kernel kern = clCreateKernel(prog, "md5_kernel", &err);

    // Create buffers
    cl_mem inbuf_dev = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, N*64, inbuf, &err);
    cl_mem outbuf_dev = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, N*16, NULL, &err);

    // set args: (inbuf, outbuf, stride)
    uint32_t stride = 64;
    clSetKernelArg(kern, 0, sizeof(cl_mem), &inbuf_dev);
    clSetKernelArg(kern, 1, sizeof(cl_mem), &outbuf_dev);
    clSetKernelArg(kern, 2, sizeof(uint32_t), &stride);

    size_t global = N;
    err = clEnqueueNDRangeKernel(q, kern, 1, NULL, &global, NULL, 0, NULL, NULL);
    clFinish(q);

    unsigned char *out = malloc(N*16);
    clEnqueueReadBuffer(q, outbuf_dev, CL_TRUE, 0, N*16, out, 0, NULL, NULL);

    // print results
    for (int i=0;i<N;i++) {
        printf("%s -> ", candidates[i]);
        for (int j=0;j<16;j++) printf("%02x", out[i*16 + j]);
        printf("\n");
    }

    // cleanup (omitted for brevity)
    free(inbuf); free(out); free(kernel_src);
    clReleaseMemObject(inbuf_dev); clReleaseMemObject(outbuf_dev);
    clReleaseKernel(kern); clReleaseProgram(prog); clReleaseCommandQueue(q); clReleaseContext(ctx);
    return 0;
}
