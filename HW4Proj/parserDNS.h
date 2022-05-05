#pragma once
#include "pch.h"


using namespace std;
class ParserDNS {
public:
	char* buf;
	int recvBytes;
	int id;
	char* resPacket;
	FixedDNSHeader* dhRes;
	ParserDNS(char* buf_in, int resSize_in);
	bool checkPkt();
	bool printQuestions();
	bool printAnswers();
	
	bool printRR(int number);
	string decodeStrDNS(char* curPkt);
	string getHostName();
	string getRR(int number);
};
