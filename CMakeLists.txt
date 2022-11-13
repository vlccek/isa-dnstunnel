cmake_minimum_required(VERSION 3.20)
project(dnstunnel C)

set(CMAKE_C_STANDARD 99)

file(GLOB reciverfiles
        "reciver/*.h"
        "reciver/*.c"
        )

add_executable(dns_receiver ${reciverfiles})

file(GLOB senderfiles
        "sender/*.h"
        "sender/*.c"
        )

add_executable(dns_sender ${senderfiles})
