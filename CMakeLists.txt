cmake_minimum_required(VERSION 3.20)
project(dnstunnel C)

set(CMAKE_C_STANDARD 99)


add_library(base16 base16.c base16.h)
add_executable(dns_receiver common.c common.h server.c server.h dns_receiver_events.c dns_receiver_events.h dns.c dns.h)
add_executable(dns_sender common.c common.h client.c client.h dns_sender_events.c dns_sender_events.h dns.c dns.h)

target_link_libraries(dns_sender base16)
target_link_libraries(dns_receiver base16)
