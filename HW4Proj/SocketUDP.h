
#include "pch.h"
#pragma once
class SocketUDP {
public:
	SOCKET sock;
	struct sockaddr_in local;
	struct sockaddr_in remote;
	int resBytes;

	SocketUDP();
	bool bindUDP();
	void setRemoteSocket(char* IP, int port);
	bool sendUDP(char* packet, int packetSize);
	bool readUDP(char* buf, timeval* timeout);
	bool readUDPNonB(char* buf);
	void close();
};
