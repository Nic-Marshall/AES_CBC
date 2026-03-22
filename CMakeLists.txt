cmake_minimum_required(VERSION 3.25)
project(LearningProjects)

set(CMAKE_CXX_STANDARD 23)

add_executable(LearningProjects main.cpp
        AES.cpp
        AES_FASTER.cpp
        time_accumulator.cpp)
