#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <ctime>
#include <chrono>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("I'm OCAll, print: %s, complete.\n", str);
}

void ocall_copy(const char* ary) {
    const char * t = ary;
    int size = 5;
    for (int i = 1 ; i < size; i++) {
        printf("I'm OCAll copy, print array: %s, complete.\n", (int)ary[i]);
    }   
}

int main(int argc, char const *argv[]) {
    std::cout << "###########################" << std::endl;
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    int ptr;
    sgx_status_t status = generate_random_number(global_eid, &ptr);
    
    if (status != SGX_SUCCESS) {
        std::cout << "noob, failed!" << std::endl;
    }
    else {
        std::cout << "Success! Status: "<<status << std::endl;
    }
    printf("Random number: %d\n", ptr);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    printf("sealed_size : %d, origin ptr size: %d\n", sealed_size, sizeof(ptr));
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back: " << unsealed << std::endl;
    
    // memory copy test 
    std::cout << "###########################" << std::endl;
    std::cout << "enclave in-out copy test" << std::endl;
    const size_t buf_len = 256*1024;  
    float * buffer = new float [buf_len];
    for (int i = 0; i < 10; i++) {
        buffer[i] = i;
    }
    std::cout << "Before ecall, buffer[0] = " << buffer[0] <<", buffer[1] = "<<buffer[1]<< std::endl;

    int repetition = 10;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < repetition ; i++){
        ecall_hello_from_enclave(global_eid, buffer, buf_len);
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds = end-start;
    auto spent_time = elapsed_seconds.count()/repetition;

    std::cout << "After ecall, buffer[0] = " << buffer[0] <<", buffer[1] = "<<buffer[1]<< std::endl;
    std::cout << repetition << " repetitions, "<<"spend " << spent_time*1000 << "ms (Avg) " << std::endl;
    
    std::cout << "###########################" << std::endl;
    std::cout << "enclave 1MB calc test" << std::endl;
    const size_t buf_len_calc = 256*1024;  
    float * buffer_1 = new float [buf_len_calc];   //256*1024*4 = 1MB
    float * buffer_2 = new float [buf_len_calc];
    for (int i = 0; i < buf_len_calc; i++) {
        buffer_1[i] = i;
        buffer_2[i] = i;
    }
    std::cout << "Before ecall, buffer_1[99] = " << buffer_1[99] <<", buffer_2[99] = "<<buffer_2[99]<< std::endl;

    float * buffer_return = new float [buf_len_calc];
    
    auto start_calc = std::chrono::steady_clock::now();
    for (int i = 0; i < repetition ; i++){
        enclave_calc_add_1MB(global_eid,&buffer_return, buffer_1,buffer_2, buf_len);
    }
    auto end_calc = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed_seconds_calc = end_calc-start_calc;
    auto spent_time_calc = elapsed_seconds_calc.count()/repetition;

    std::cout << "After ecall, buffer_1[99] = " << buffer_1[99] <<", buffer_2[99] = "<<buffer_2[99]<< std::endl;
    std::cout << "After ecall, buffer_return[0] = " << buffer_return[0] <<", buffer_return[1] = "<<buffer_return[1]<<", buffer_return[5] = "<<buffer_return[5]<< std::endl;
    std::cout <<"1MB add calc, " <<repetition << " repetitions, "<<"spend " << spent_time_calc*1000 << "ms (Avg) " << std::endl;

    return 0;
}
