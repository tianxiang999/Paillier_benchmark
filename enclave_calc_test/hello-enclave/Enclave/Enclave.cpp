#include "Enclave_t.h"
#include <string.h>

int generate_random_number() {
    ocall_print("Ecall(generate_random_number) call Ocall: Processing random number generation...(42)");
    // print("ecall print")
    return 42;
}

int* mallocer() {
    int size=1 * 1024 / 4;
    int * t = new int [size];
    for (int i = 1 ; i < size; i++) {
        t[i] = i;
    }
    // ocall_copy(t);

    // char* pt = "tianxiang";
    // ocall_print(pt);
    
    return t;
}

// public void ecall_hello_from_enclave([out, size=len] int* buf, size_t len);
void ecall_hello_from_enclave(float *buf, size_t len)
{
    buf[0] = 888;
    buf[1] = 999;
}

float* enclave_calc_add_1MB(float *buf_1, float *buf_2, size_t len)
{
    size_t size = len;
    float * hello = new float [size];
    for (int i = 0; i < size; i++) {
        hello[i] = buf_1[i]+buf_2[i];
    }
    return hello;
}