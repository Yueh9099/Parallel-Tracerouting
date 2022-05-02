// HW4Proj.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "SocketUDP.h"
#include "parserDNS.h"
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#define IP_HDR_SIZE 20
#define ICMP_HDR_SIZE 8
#define MAX_SIZE 65200
#define MAX_ICMP_SIZE (MAX_SIZE+ICMP_HDR_SIZE)
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)

/* ICMP packet types */
#define ICMP_ECHO_REPLY 0 
#define ICMP_DEST_UNREACH 3 
#define ICMP_TTL_EXPIRED 11 
#define ICMP_ECHO_REQUEST 8 

#define ICMP 1

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

class routerInfor {
public:
	int seq;
	char* hostName;
	DWORD ip;
	double RTT;
	bool recvIP;
};

/* remember the current packing state */
#pragma pack (push) 
#pragma pack (1) 

/* define the IP header (20 bytes) */
class IPHeader {
public:
	u_char h_len : 4; /* lower 4 bits: length of the header in dwords */
	u_char version : 4; /* upper 4 bits: version of IP, i.e., 4 */
	u_char tos; /* type of service (TOS), ignore */
	u_short len; /* length of packet */
	u_short ident; /* unique identifier */
	u_short flags; /* flags together with fragment offset - 16 bits */
	u_char ttl; /* time to live */
	u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum; /* IP header checksum */
	u_long source_ip;
	u_long dest_ip;
};


/* define the ICMP header (8 bytes) */
class ICMPHeader {
public:
	u_char type; /* ICMP packet type */
	u_char code; /* type subcode */
	u_short checksum; /* checksum of the ICMP */
	u_short id; /* application-specific ID */
	u_short seq; /* application-specific sequence */
};


/* now restore the previous packing state */
#pragma pack (pop) 

u_short ip_checksum(u_short* buffer, int size)
{
	u_long cksum = 0;

	/* sum all the words together, adding the final byte if size is odd */
	while (size > 1)
	{
		cksum += *buffer++;
		size -= sizeof(u_short);
	}
	if (size) {
		cksum += *(u_char*)buffer;
	}
	

	/* add carry bits to lower u_short word */
	cksum = (cksum >> 16) + (cksum & 0xffff);

	/* return a bitwise complement of the resulting mishmash */
	return (u_short)(~cksum);
}

//source:https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams
int getDNSServer(char* dnsServerIP, int size) {
	FIXED_INFO* pFixedInfo;
	ULONG ulOutBufLen;
	DWORD dwRetVal;
	IP_ADDR_STRING* pIPAddr;

	pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
	if (pFixedInfo == NULL) {
		printf("Error allocating memory needed to call GetNetworkParams\n");
		return 0;
	}
	ulOutBufLen = sizeof(FIXED_INFO);
// Make an initial call to GetAdaptersInfo to get
// the necessary size into the ulOutBufLen variable
	if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		FREE(pFixedInfo);
		pFixedInfo = (FIXED_INFO*)MALLOC(ulOutBufLen);
		if (pFixedInfo == NULL) {
			printf("Error allocating memory needed to call GetNetworkParams\n");
			return 0;
		}
	}
	if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) == NO_ERROR) {
		
		
		
		memcpy(dnsServerIP,pFixedInfo->DnsServerList.IpAddress.String,size);
		if (pFixedInfo)
			FREE(pFixedInfo);
		
		
		return 1;
		

	}
	else {
		printf("GetNetworkParams failed with error: %d\n", dwRetVal);
		return 0;
	}

	if (pFixedInfo)
		FREE(pFixedInfo);

	return 0;
}


int main(int argc, char** argv)
{
	if (argc != 2) {
		printf("Usage:hostname/IP");
		exit(-1);
	}
	char* host = argv[1];
	printf("host is %s\n",host);

	//get local dns server
	char localDNSServer[16];
	if (getDNSServer(localDNSServer,16) == 0) {
		printf("cannot get the local dns server IP\n");
	}
	//printf("local dns:%s\n",localDNSServer);
	
	// WAS initialization
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		printf("WSAStartup error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	// get remote(ping) address information
	sockaddr_in pingAddr;
	struct hostent* remote;
	memset(&pingAddr, 0, sizeof(sockaddr_in));
	
	pingAddr.sin_family = AF_INET;

	DWORD IP = inet_addr(host);
	if (IP == INADDR_NONE) {
		if ((remote = gethostbyname(host)) == NULL) {
			printf("invalid host name\n");
			exit(-1);
		}
		memcpy(&pingAddr.sin_addr, remote->h_addr, remote->h_length);
		//printf("IP is: %s\n",remote->h_addr);
	}
	else {
		pingAddr.sin_addr.S_un.S_addr = IP;
	}
	

	// socket setup
	SOCKET sendSocket;
	sendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sendSocket == INVALID_SOCKET) {
		printf("socket() generate error %d", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
	
	//prepare sending buffer
	u_char sendBuf[MAX_ICMP_SIZE];
	ICMPHeader* icmp = (ICMPHeader*)sendBuf;
	icmp->type = ICMP_ECHO_REQUEST;
	icmp->code = 0;
	icmp->id = (u_short)GetCurrentProcessId();
	icmp->seq = 1;
	icmp->checksum = 0;
	icmp->checksum = ip_checksum((u_short*)sendBuf, ICMP_HDR_SIZE);
	int bufLen = ICMP_HDR_SIZE;
	// send the ICMP pkt
	int ttl = 20;
	if (setsockopt(sendSocket, IPPROTO_IP,IP_TTL,(const char*) &ttl,sizeof(ttl)) == SOCKET_ERROR) {
		printf("setsocketopt failed with %d\n",WSAGetLastError());
		closesocket(sendSocket);
		exit(-1);
	}

	int sendResult;
	sendResult = sendto(sendSocket, (const char*)sendBuf, bufLen, 0, (sockaddr*)&pingAddr, sizeof(pingAddr));
	if (sendResult == SOCKET_ERROR) {
		printf("send failed with error %d\n", WSAGetLastError());
		WSACleanup();
		closesocket(sendSocket);
		exit(-1);
	}

	//receive and parse ICMP
	u_char recBuf[MAX_REPLY_SIZE];
	IPHeader* router_ip_hdr = (IPHeader*)recBuf;
	ICMPHeader* router_icmp_hdr = (ICMPHeader*)(router_ip_hdr +1);
	IPHeader* origi_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
	ICMPHeader* origi_icmp_hdr = (ICMPHeader*)(origi_ip_hdr + 1);

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(sendSocket, &readfds);
	timeval timeout;
	timeout.tv_sec = 1000;
	timeout.tv_usec = 0;
	int ret;
	int recvBytes;
	SOCKADDR remoteAddr;
	int remoteLen = sizeof(SOCKADDR);

	if ((ret = select(0, &readfds, NULL, NULL, &timeout))==SOCKET_ERROR) {
		printf("select() failed with %d\n", WSAGetLastError());

	}
	else if (ret == 0) {
		printf("Time out on select()\n");
	}
	// ready for receive
	else
	{
		//printf("I can receive ICMP now!\n");
		if ((recvBytes = recvfrom(sendSocket, (char*)recBuf, MAX_REPLY_SIZE, 0, &remoteAddr, &remoteLen)) == SOCKET_ERROR) {
			printf("recfrom() failed with %d\n",WSAGetLastError());
			exit(-1);
		}
		else if (recvBytes == 0) {
			printf("recvfrom() error\n");
			exit(-1);
		}
		// then receive successfully
	}

	//prepare the udp socket for dns
	SocketUDP dnsSocket;
	if (!dnsSocket.bindUDP()) {
		printf("DNS Socket local bind error %d\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}
	socketUDP.setRemoteSocket(localDNSServer, 53);

	DWORD srcIP = 0;
	if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0) {
		if (origi_ip_hdr->proto == ICMP) {
			if (origi_icmp_hdr->id == GetCurrentProcessId()) {
				srcIP = router_ip_hdr->source_ip;
			}
		}
	}


	

	
	


}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
