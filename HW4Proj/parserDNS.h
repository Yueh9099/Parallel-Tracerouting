#pragma once
#include "pch.h"

#pragma pack(push, 1)
class QueryHeader {
public:
	USHORT qType;
	USHORT qClass;
};

class FixedDNSHeader {
public:
	USHORT ID;
	USHORT flags;
	USHORT questions;
	USHORT answers;
	USHORT authority;
	USHORT additional;
};

class DNSanswerHdr {
public:
	u_short qType;
	u_short qClass;
	u_int TTL;
	u_short len;
};
#pragma pack(pop)
using namespace std;
class ParserDNS {
public:
	char* buf;
	int recvBytes;
	char* resPacket;
	FixedDNSHeader* dhRes;
	FixedDNSHeader* dh;
	ParserDNS(char* buf_in, int resSize_in, char* sendPkt);
	bool checkPkt();
	bool printQuestions();
	bool printAnswers();
	bool printAuthority();
	bool printAdditional();
	bool printRR(int number);
	string decodeStrDNS(char* curPkt);
};
