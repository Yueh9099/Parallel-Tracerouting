#include"pch.h"
#include "SocketUDP.h"

SocketUDP::SocketUDP() {
    sock = socket(AF_INET, SOCK_DGRAM, 0);
}

bool SocketUDP::bindUDP() {
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);

    if (sock == INVALID_SOCKET) {
        printf("fail to create the socket\n");
        closesocket(sock);
        WSACleanup();
        return false;
    }

    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }

    return true;
}

void SocketUDP::setRemoteSocket(char* IP, int port) {
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.S_un.S_addr = inet_addr(IP);
    remote.sin_port = htons(port);
}

bool SocketUDP::sendUDP(char* packet, int packetSize) {
    if (sendto(sock, packet, packetSize, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
        closesocket(sock);
        return false;
    }
    return true;
}

bool SocketUDP::readUDPNonB(char* buf) {
    struct sockaddr_in response;
    int size = sizeof(response);


    if ((resBytes = recvfrom(sock, buf, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &size)) == SOCKET_ERROR) {
        printf("Socket receive error %d\n", WSAGetLastError());
        closesocket(sock);
        return false;
    }
    //check if this packet came from the server to which we sent the query earlier 
    if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port) {
        printf("Invalid IP or port\n");
        closesocket(sock);
        return false;
    }
    return true;
}

bool SocketUDP::readUDP(char* buf, timeval* timeout) {
    fd_set fd;
    FD_ZERO(&fd);
    FD_SET(sock, &fd);


    // Successful response
    if (select(0, &fd, NULL, NULL, timeout) > 0) {

        struct sockaddr_in response;
        int size = sizeof(response);


        if ((resBytes = recvfrom(sock, buf, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &size)) == SOCKET_ERROR) {
            printf("Socket receive error %d\n", WSAGetLastError());
            closesocket(sock);
            return false;
        }
        //check if this packet came from the server to which we sent the query earlier 
        if (response.sin_addr.s_addr != remote.sin_addr.s_addr || response.sin_port != remote.sin_port) {
            printf("Invalid IP or port\n");
            closesocket(sock);
            return false;
        }
        return true;
    }
    closesocket(sock);
    printf("\ttimeout in 10000 ms\n");
    return false;
}





void SocketUDP::close() {
    closesocket(sock);
}