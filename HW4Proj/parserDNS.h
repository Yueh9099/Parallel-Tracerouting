#pragma once
#include "pch.h"


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
	string getHostName();
	string getRR(int number);
};
