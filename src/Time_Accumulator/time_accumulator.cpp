//
// Created by Nicho on 1/24/2024.
//

#include "time_accumulator.h"
#include <cstdio>

void time_accumulator::timer_start_timing() {
    time_start = std::chrono::high_resolution_clock::now();
}

void time_accumulator::timer_log_time(int idx) {
    times[idx] += std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - time_start);
    time_start = std::chrono::high_resolution_clock::now();
}

void time_accumulator::add_new_tracker() {
    times.push_back(std::chrono::microseconds(0));
}

unsigned long long time_accumulator::get_time(int idx) {
    return times[idx].count();
}

void time_accumulator::report_times() {
    for(int i = 0; i < 4; i++) {
        std::printf("Timer index %d accumulated %lld microseconds\n", i, times[i].count());
    }
}
