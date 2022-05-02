#include "pch.h"
#include "QueryGenerator.h"



void makeDNSQuestion(char* buf, char* host) {
	char* curP;
	char* tempHost = host;
	int nextSize = 0;
	int i = 0;

	while ((curP = strstr(tempHost, ".")) != NULL) {
		nextSize = curP - tempHost;
		buf[i++] = nextSize;
		memcpy(buf + i, tempHost, nextSize);
		i += nextSize;
		tempHost = curP + 1;
	}
	//now curP == NULL
	nextSize = strlen(tempHost);
	buf[i++] = nextSize;
	memcpy(buf + i, tempHost, nextSize);
	i += nextSize;
	buf[i] = 0;
}

QueryGenerator::QueryGenerator(const char* hostOrIP_in, const char* dnsServer_in) {
	hostOrIP = hostOrIP_in;
	dnsServer = dnsServer_in;
}



void QueryGenerator::generatePacket(int ID_In) {
	ID = htons(ID_In);
	DWORD IP_addr = inet_addr(hostOrIP);
	//inverse query
	if (IP_addr != INADDR_NONE)
	{
		DWORD reversedIP = htonl(IP_addr);
		struct in_addr paddr;
		paddr.S_un.S_addr = reversedIP;
		queryStr = inet_ntoa(paddr);
		if (queryStr == NULL) {
			printf("reverse IP adress fails\n");
			return;
		}
		strcat(queryStr, ".in-addr.arpa");
		qType = htons(DNS_PTR);

	}
	//standard query
	else {
		queryStr = new char[strlen(hostOrIP) + 1];
		strcpy(queryStr, hostOrIP);
		qType = htons(DNS_A);

	}


	packetSize = strlen(queryStr) + 2 + sizeof(FixedDNSHeader) + sizeof(QueryHeader);
	packet = new char[MAX_DNS_LEN];
	FixedDNSHeader* dh = (FixedDNSHeader*)packet;
	QueryHeader* qh = (QueryHeader*)(packet + packetSize - sizeof(QueryHeader));

	qh->qType = qType;
	qh->qClass = htons(DNS_INET);

	dh->ID = ID;
	dh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
	dh->questions = htons(1);
	dh->answers = htons(0);
	dh->authority = htons(0);
	dh->additional = htons(0);

	makeDNSQuestion((char*)(dh + 1), queryStr);

}