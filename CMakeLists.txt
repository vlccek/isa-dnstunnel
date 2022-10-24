cmake_minimum_required(VERSION 3.20)
project(dnstunnel C)

set(CMAKE_C_STANDARD 99)

add_executable(dns_receiver receiver/server.h receiver/server.c receiver/dns_receiver_events.c receiver/dns_receiver_events.h)
add_executable(dns_sender sender/dns_sender_events.c sender/dns_sender_events.h)
