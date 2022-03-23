#include <stdio.h>
#include <iostream>
#include <ctime>
#include <unistd.h>
#include <chrono>

int main(){
    int rep = 10;

    auto start = std::chrono::steady_clock::now();
    sleep(2);
    auto end = std::chrono::steady_clock::now();
    auto duration = end - start;
    std::chrono::duration<double> elapsed_seconds = end-start;

    std::cout<< elapsed_seconds.count()*1000<<"ms"<<std::endl;
}