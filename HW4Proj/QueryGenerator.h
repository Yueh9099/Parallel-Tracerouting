#pragma once
#include "pch.h"


class QueryGenerator {

public:
	const char* hostOrIP;
	const char* dnsServer;
	u_short qType;
	u_short ID;
	char* queryStr;
	char* queryName;
	int packetSize;
	short opcode;
	char* query;
	char* packet;

	QueryGenerator(const char* hostOrIP_in, const char* dnsServer);

	void generatePacket(int ID_in);

};