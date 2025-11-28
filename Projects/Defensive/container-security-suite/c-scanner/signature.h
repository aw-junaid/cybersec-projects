#ifndef SIGNATURE_H
#define SIGNATURE_H

typedef struct {
    int risk_score;
    int critical_count;
    int high_count;
    int signature_verified;
    int passed;
    double scan_duration;
} scan_result_t;

#endif
