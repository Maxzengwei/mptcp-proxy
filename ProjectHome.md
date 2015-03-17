Note:

> This piece of work is only a student final project conducted in only two month and no one is still (or will continue) working on it. The code is made only to test if our theory is correct. The implementation is ugly and inefficient and is not helpful on practical usage.



MPTCP Proxy Abstract

MPTCP has been proved by research that it can improve the TCP throughputs, especially in realizing a smoother handoff between 3G and Wi-Fi in mobility cases. However, a host can only benefit from MPTCP if the targeted server also supports MPTCP but currently most of the servers don’t. That inspires the idea of implementing an MPTCP proxy which can help an MPTCP client to establish MPTCP connection with a legacy TCP server.



We propose the idea of implementing an implicit MPTCP proxy which deployed in the direct routing path between the client and server, and perform MPTCP functions by intercepting and injecting the packets to allow the MPTCP client establishing multiple flows in one session with a normal TCP sever. The project will first focus on investigating how real MPTCP client-server operations behave how each MPTCP functions contribute to give the benefits. Then the project will focus on implementing the proxy which can realize the functions above, especially on two issues: a) how to establish the connection transparently and b) how to transfer the data sequence correctly. We will define the rules of how this proxy should react as a state machine, and discover what exact content we need to inject in the packet.