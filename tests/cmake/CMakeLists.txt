cmake_minimum_required(VERSION 3.31.0)
project(ClientOfHyphaIp LANGUAGES C VERSION 1.0.0)

find_package(HyphaIp REQUIRED)

add_executable(client_of_hypha_ip ../../examples/hypha_ip_lifecycle.c)
target_link_libraries(client_of_hypha_ip PRIVATE HyphaIp::hypha-ip)

