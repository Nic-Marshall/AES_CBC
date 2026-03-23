//
// Created by Nicho on 1/24/2024.
//

#ifndef LEARNINGPROJECTS_PROFILE_ACCUMULATOR_H
#define LEARNINGPROJECTS_PROFILE_ACCUMULATOR_H

#include <vector>
#include <chrono>

class time_accumulator {
public:
    std::vector<std::chrono::microseconds> times;
    std::chrono::time_point<std::chrono::high_resolution_clock> time_start;
    std::chrono::time_point<std::chrono::high_resolution_clock> time_end;

    void timer_start_timing();

    void timer_log_time(int idx);

    void add_new_tracker();

    void report_times();

    unsigned long long get_time(int idx);
};


#endif //LEARNINGPROJECTS_PROFILE_ACCUMULATOR_H
