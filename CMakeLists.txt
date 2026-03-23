cmake_minimum_required(VERSION 3.25)
project(LearningProjects)

set(CMAKE_CXX_STANDARD 23)

add_executable(LearningProjects src/main.cpp
        src/AES_CBC.cpp
        src/time_accumulator.cpp
        src/test_cases.cpp)
