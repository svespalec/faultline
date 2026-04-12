cmake_minimum_required( VERSION 4.1 )
project( faultline LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 23 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )

add_executable( faultline main.cpp )
