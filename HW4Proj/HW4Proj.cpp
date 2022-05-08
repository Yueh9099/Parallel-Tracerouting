// HW4Proj.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "SocketUDP.h"
#include "parserDNS.h"
#include "QueryGenerator.h"
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

class RouterInfo {
public:
	string hostName;
	string ip;
	long long int RTTmicroseconds = 0;
	long long int RTOC = 0;
	int transTimes = 1;// to make it simpler, first 30 pkts sending is counted here
	int type = 0;
	int code = 0;
	bool recvIP = false;
	bool recvHostName = false;;
	bool isEchoRply = false;
	bool isOtherError = false;

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



		memcpy(dnsServerIP, pFixedInfo->DnsServerList.IpAddress.String, size);
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
	//printf("host is %s\n", host);
	LARGE_INTEGER TraceroutingStart;
	QueryPerformanceCounter(&TraceroutingStart);

	//get local dns server
	char localDNSServer[16];
	if (getDNSServer(localDNSServer, 16) == 0) {
		printf("cannot get the local dns server IP\n");
	}
	//printf("local dns:%s\n", localDNSServer);

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
	char hostIP[16];
	inet_ntop(AF_INET, &(pingAddr.sin_addr), hostIP, 16);
	printf("Tracerouting to %s...\n",hostIP);

	// ICMP socket setup
	SOCKET sockICMP;
	sockICMP = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockICMP == INVALID_SOCKET) {
		printf("socket() generate error %d", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}

	LARGE_INTEGER Frequency;
	if (QueryPerformanceFrequency(&Frequency) == 0) {
		printf("QueryPerformanceFrequency fail\n");
	}
	// make a router information array
	RouterInfo routerInfo[30];

	//making ICMP pkts
	DWORD processID = GetCurrentProcessId();
	char icmpBufers[30][ICMP_HDR_SIZE];
	for (int i = 0; i < 30; i++) {
		ICMPHeader* icmp = (ICMPHeader*)icmpBufers[i];
		icmp->type = ICMP_ECHO_REQUEST;
		icmp->code = 0;
		icmp->id = (u_short)processID;
		icmp->seq = i + 1;
		icmp->checksum = 0;
		icmp->checksum = ip_checksum((u_short*)icmpBufers[i], ICMP_HDR_SIZE);
		routerInfo[i].RTOC = 0.5 * Frequency.QuadPart;//set RTO for each router
	}

	// DNS socket setup

	SocketUDP dnsSocketWrap;
	if (!dnsSocketWrap.bindUDP()) {
		printf("DNS Socket local bind error %d\n", WSAGetLastError());
		WSACleanup();
		exit(-1);
	}
	dnsSocketWrap.setRemoteSocket(localDNSServer, 53);
	SOCKET sockDNS = dnsSocketWrap.sock;

	//set receive events
	HANDLE recvICMP = CreateEvent(NULL, FALSE, FALSE, NULL);
	HANDLE recvDNS = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (WSAEventSelect(sockICMP, recvICMP, FD_READ) == SOCKET_ERROR) {
		printf("WSAEventSelect fail\n");
		exit(-1);
	}
	if (WSAEventSelect(sockDNS, recvDNS, FD_READ) == SOCKET_ERROR) {
		printf("WSAEventSelect fail\n");
		exit(-1);
	}
	HANDLE hEvents[2];
	hEvents[0] = recvICMP;
	hEvents[1] = recvDNS;

	

	//set time counter variables
	LARGE_INTEGER CurrentTimeC, ElapsedMicrosecondsC, TimeOutMilliseconds;
	LARGE_INTEGER StartingTimesC[30];
	LARGE_INTEGER TimeExpiresC[31];
	
	
	//set paramters used in while loop for receiving ICMP pkts
	bool complete = false;
	DWORD dwEvent;
	LARGE_INTEGER TimeExpireJC;
	TimeExpireJC.QuadPart = INT64_MAX;
	int j;

	/*
	LARGE_INTEGER testSendTime;
	QueryPerformanceCounter(&testSendTime);
	*/
	// send the ICMP pkts
	int ttl = 0;
	for (int i = 0; i < 30; i++) {

		ttl = i + 1;
		ICMPHeader* icmp = (ICMPHeader*)icmpBufers[i];
		//printf("sending pkt with seq: %d ", icmp->seq);
		if (setsockopt(sockICMP, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
			printf("setsocketopt failed with %d\n", WSAGetLastError());
			closesocket(sockICMP);
			exit(-1);
		}
		int sendSize;
		if ((sendSize = sendto(sockICMP, (const char*)icmpBufers[i], ICMP_HDR_SIZE, 0, (sockaddr*)&pingAddr, sizeof(pingAddr))) == SOCKET_ERROR) {
			printf("send failed with error %d\n", WSAGetLastError());
			WSACleanup();
			closesocket(sockICMP);
			exit(-1);
		}
		if (QueryPerformanceCounter(&StartingTimesC[i]) == 0) {
			printf("QueryPerformanceCounter fail\n");
		}
		TimeExpiresC[i].QuadPart = StartingTimesC[i].QuadPart +routerInfo[i].RTOC;
		//printf("sent %d bytes\n", sendSize);
	}
	TimeExpiresC[30].QuadPart = StartingTimesC[0].QuadPart + 5 * Frequency.QuadPart;
	
	/*
	QueryPerformanceCounter(&CurrentTime);
	ElapsedMicroseconds.QuadPart = CurrentTime.QuadPart - TimeExpires[30].QuadPart;
	ElapsedMicroseconds.QuadPart *= 1000000;
	ElapsedMicroseconds.QuadPart /= Frequency.QuadPart;
	printf("test the timeout is %fms\n", (double)(ElapsedMicroseconds.QuadPart) / 1000);
	*/

	//receive ICMP, parse,retransmission, DNS lookup
	
	while (true) {

		

		for (int i = 0; i < 31; i++) {
			if (TimeExpiresC[i].QuadPart < TimeExpireJC.QuadPart) {
				TimeExpireJC.QuadPart = TimeExpiresC[i].QuadPart;
				j = i;
			}
		}
		if (TimeExpireJC.QuadPart == INT64_MAX) {
			break;
		}
		QueryPerformanceCounter(&CurrentTimeC);
		TimeOutMilliseconds.QuadPart = TimeExpireJC.QuadPart - CurrentTimeC.QuadPart;
		TimeOutMilliseconds.QuadPart *= 1000;
		TimeOutMilliseconds.QuadPart = TimeOutMilliseconds.QuadPart/ Frequency.QuadPart;
		TimeExpireJC.QuadPart = INT64_MAX;

		//printf("waiting the %dth pkt, and timeout is %dms\n",j, TimeOutMilliseconds.QuadPart);
		if (TimeOutMilliseconds.QuadPart < 0) {
			TimeOutMilliseconds.QuadPart = 0;
		}
		dwEvent = WaitForMultipleObjects(2, hEvents, false, TimeOutMilliseconds.QuadPart);

		switch (dwEvent)
		{
		case WAIT_OBJECT_0:
		{
			QueryPerformanceCounter(&CurrentTimeC);
			//rececive the ICMP pkt
			u_char recBuf[MAX_REPLY_SIZE];
			int recvBytesICMP;
			SOCKADDR remoteAddr;
			int remoteLen = sizeof(SOCKADDR);
			if ((recvBytesICMP = recvfrom(sockICMP, (char*)recBuf, MAX_REPLY_SIZE, 0, &remoteAddr, &remoteLen)) == SOCKET_ERROR) {
				printf("recfrom() failed with %d\n", WSAGetLastError());
				exit(-1);
			}
			else if (recvBytesICMP == 0) {
				printf("recvfrom() error\n");
				exit(-1);
			}
			

			//parse the icmp pkt
			IPHeader* router_ip_hdr = (IPHeader*)recBuf;
			int ipheaderLen = router_ip_hdr->h_len * 4;
			ICMPHeader* router_icmp_hdr = (ICMPHeader*)(recBuf + ipheaderLen);
			if (router_ip_hdr->proto == ICMP) {
				//icmp echo reply pkt
				if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == 0) {
					if (router_icmp_hdr->id == processID) {
						

						char srcIP[16];
						struct sockaddr_in sa;
						sa.sin_addr.S_un.S_addr = router_ip_hdr->source_ip;
						if (inet_ntop(AF_INET, &(sa.sin_addr), srcIP, sizeof(srcIP)) == NULL) {
							printf("received IP is invalid\n");
							break;
						}
						ElapsedMicrosecondsC.QuadPart = CurrentTimeC.QuadPart - StartingTimesC[router_icmp_hdr->seq - 1].QuadPart;
						ElapsedMicrosecondsC.QuadPart *= 1000000;
						routerInfo[router_icmp_hdr->seq - 1].recvIP = true;
						routerInfo[router_icmp_hdr->seq - 1].isEchoRply = true;
						routerInfo[router_icmp_hdr->seq - 1].ip = srcIP;
						routerInfo[router_icmp_hdr->seq - 1].RTTmicroseconds =ElapsedMicrosecondsC.QuadPart/ Frequency.QuadPart;

						for (int k = 0; k < router_icmp_hdr->seq - 1; k++) {
							if (TimeExpiresC[k].QuadPart != INT64_MAX) {
								if (k == router_icmp_hdr->seq - 2 && TimeExpiresC[k - 1].QuadPart == INT64_MAX) {
									routerInfo[k].RTOC = (routerInfo[k - 1].RTTmicroseconds + routerInfo[k + 1].RTTmicroseconds) * Frequency.QuadPart / 1000000;
									TimeExpiresC[k].QuadPart = StartingTimesC[k].QuadPart + routerInfo[k].RTOC;

								}
								else {
									routerInfo[k].RTOC = 2 * (CurrentTimeC.QuadPart - StartingTimesC[router_icmp_hdr->seq - 1].QuadPart);
									TimeExpiresC[k].QuadPart = StartingTimesC[k].QuadPart + routerInfo[k].RTOC;

								}
							}
						}

						for (int k = router_icmp_hdr->seq - 1; k < 30; k++) {
							TimeExpiresC[k].QuadPart = INT64_MAX;//do not wait this pkt anymore

						}
						//printf("the host ip is: %s\n", srcIP);
						// send the dns query pkt
						QueryGenerator queryG(srcIP, localDNSServer);
						queryG.generatePacket(router_icmp_hdr->seq);
						if (!dnsSocketWrap.sendUDP(queryG.packet, queryG.packetSize)) {
							printf("Socket send error %d\n", WSAGetLastError());

							WSACleanup();
							exit(-1);
						}
						//printf("receive icmp echo reply, sent dns seq: %d\n", router_icmp_hdr->seq);

					}
				}
				// icmp TTL out pkt
				else if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == 0) {

					IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
					ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);
					if (orig_ip_hdr->proto == ICMP && orig_icmp_hdr->id == processID) {
						char srcIP[16];
						struct sockaddr_in sa;
						sa.sin_addr.S_un.S_addr = router_ip_hdr->source_ip;
						if (inet_ntop(AF_INET, &(sa.sin_addr), srcIP, sizeof(srcIP)) == NULL) {
							printf("received IP is invalid\n");
							break;
						}
						ElapsedMicrosecondsC.QuadPart = CurrentTimeC.QuadPart - StartingTimesC[orig_icmp_hdr->seq - 1].QuadPart;
						ElapsedMicrosecondsC.QuadPart *= 1000000;
						routerInfo[orig_icmp_hdr->seq - 1].recvIP = true;
						routerInfo[orig_icmp_hdr->seq - 1].ip = srcIP;
						routerInfo[orig_icmp_hdr->seq - 1].RTTmicroseconds = (ElapsedMicrosecondsC.QuadPart) / Frequency.QuadPart;
						TimeExpiresC[orig_icmp_hdr->seq - 1].QuadPart = INT64_MAX;//do not wait the pkt anymore

						for (int k = 0; k < orig_icmp_hdr->seq - 1; k++) {
							if (TimeExpiresC[k].QuadPart != INT64_MAX) {
								if (k == orig_icmp_hdr->seq - 2 && TimeExpiresC[k - 1].QuadPart == INT64_MAX) {
									routerInfo[k].RTOC = (routerInfo[k - 1].RTTmicroseconds + routerInfo[k + 1].RTTmicroseconds) * Frequency.QuadPart / 1000000;
									TimeExpiresC[k].QuadPart = StartingTimesC[k].QuadPart + routerInfo[k].RTOC;

								}
								else {
									routerInfo[k].RTOC = 2 * (CurrentTimeC.QuadPart - StartingTimesC[orig_icmp_hdr->seq - 1].QuadPart);
									TimeExpiresC[k].QuadPart = StartingTimesC[k].QuadPart + routerInfo[k].RTOC;

								}
							}
						}
						//early termination
						if (orig_icmp_hdr->seq== 30) {
							TimeExpiresC[30].QuadPart = INT64_MAX;
						}

						//printf("RTT is %f\n", routerInfo[orig_icmp_hdr->seq - 1].RTT);

						//printf("the router %d ip is: %s\n", orig_icmp_hdr->seq, srcIP);
						// send the dns query pkt
						QueryGenerator queryG(srcIP, localDNSServer);
						queryG.generatePacket(orig_icmp_hdr->seq);
						if (!dnsSocketWrap.sendUDP(queryG.packet, queryG.packetSize)) {
							printf("Socket send error %d\n", WSAGetLastError());

							WSACleanup();
							exit(-1);
						}
						//printf("receive icmp timeout, sent dns seq: %d\n", orig_icmp_hdr->seq);
					}

				}
				//other error
				else  {
				IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
				ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);
				if (orig_icmp_hdr->id == processID) {
					
					routerInfo[orig_icmp_hdr->seq - 1].isOtherError = true;
					routerInfo[orig_icmp_hdr->seq - 1].code = router_icmp_hdr->code;
					routerInfo[orig_icmp_hdr->seq - 1].type = router_icmp_hdr->type;
					TimeExpiresC[orig_icmp_hdr->seq - 1].QuadPart = INT64_MAX;//do not wait the pkt anymore
				}
					
				}

				break;
			}
		}
		case WAIT_OBJECT_0 + 1:
		{
			//receive the DNS response
			char buf[MAX_DNS_LEN];
			if (!dnsSocketWrap.readUDPNonB(buf)) {
				WSACleanup();
				printf("socket read fail\n");
			}
			ParserDNS parserDNS(buf, dnsSocketWrap.resBytes);
			string routerName = parserDNS.getHostName();
			int idDNS = parserDNS.id;
			//printf("receive DNS with id:%d\n",idDNS);
			

			if (routerName.empty()) {
				//printf("DNS pkt error\n");
				break;
			}
			
			routerInfo[idDNS - 1].hostName = routerName;
			routerInfo[idDNS - 1].recvHostName = true;
			if (routerInfo[idDNS - 1].isEchoRply) {
				ElapsedMicrosecondsC.QuadPart = 2 * routerInfo[idDNS - 1].RTTmicroseconds * Frequency.QuadPart;
				TimeExpiresC[30].QuadPart = StartingTimesC[0].QuadPart + ElapsedMicrosecondsC.QuadPart / 1000000;
			}
			
			
			//printf(" the router host name is %s\n", routerName.c_str());
			break;
		}
		// timeout resend the ICMP pkt
		case WAIT_TIMEOUT:
		{
			// DNS timeout
			if (j == 30) {
				TimeExpiresC[j].QuadPart = INT64_MAX;
				break;
			}
			
			// else, jth ICMP timeout
			if (routerInfo[j].transTimes < 3) {
				ttl = j + 1;
				ICMPHeader* icmp = (ICMPHeader*)icmpBufers[j];
				//printf("sending pkt with seq: %d ", icmp->seq);
				if (setsockopt(sockICMP, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
					printf("setsocketopt failed with %d\n", WSAGetLastError());
					closesocket(sockICMP);
					exit(-1);
				}
				int sendSize;
				if ((sendSize = sendto(sockICMP, (const char*)icmpBufers[j], ICMP_HDR_SIZE, 0, (sockaddr*)&pingAddr, sizeof(pingAddr))) == SOCKET_ERROR) {
					printf("send failed with error %d\n", WSAGetLastError());
					WSACleanup();
					closesocket(sockICMP);
					exit(-1);
				}
				routerInfo[j].transTimes++;

				QueryPerformanceCounter(&CurrentTimeC);
				StartingTimesC[j].QuadPart = CurrentTimeC.QuadPart;
				//
				TimeExpiresC[j].QuadPart = CurrentTimeC.QuadPart + routerInfo[j].RTOC;
			}
			else {
				if (j == 29) {
					TimeExpiresC[30].QuadPart = INT64_MAX;
				}
				TimeExpiresC[j].QuadPart = INT64_MAX;
			}
			break;
		}

		default:
			printf("waitformultipleobject error\n");
			break;
		}
	}

	QueryPerformanceCounter(&CurrentTimeC);
	ElapsedMicrosecondsC.QuadPart = CurrentTimeC.QuadPart - TraceroutingStart.QuadPart;
	ElapsedMicrosecondsC.QuadPart *= 1000;// acutually milliseconds
	ElapsedMicrosecondsC.QuadPart /= Frequency.QuadPart;
	for (int i = 0; i < 30; i++) {
		RouterInfo routerInfoI = routerInfo[i];
		printf("%d\t",i+1);
		if (!routerInfoI.recvIP) {
			printf("*");
			if (routerInfoI.isOtherError) {
				printf(" other error: code %d, type %d",routerInfoI.code,routerInfoI.type);
			}
			printf("\n");
			continue;
		}
		if (routerInfoI.recvHostName) {
			printf("%s\t", routerInfoI.hostName.c_str());
			//printf("hostname doesnot work?\t");
		}
		else {
			printf("<no DNS entry>\t");
		}
		printf("(%s)\t",routerInfoI.ip.c_str());
		printf("%.3f ms\t", (double)routerInfoI.RTTmicroseconds/1000);
		printf("(%d)\n",routerInfoI.transTimes);
		//received IP
		if (routerInfoI.isEchoRply) {
			break;
		}
	}

	printf("Total execution time: %dms",ElapsedMicrosecondsC.QuadPart);












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
