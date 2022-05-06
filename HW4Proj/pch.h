// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <string>
#include <string.h>
#include <time.h>
#include <iphlpapi.h>
#include <profileapi.h>


// DNS Query types
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */ 

//DNS Class
#define DNS_INET 1

// Flags
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)
#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */
#define DNS_INVQUERY (1 << 11)
#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */


#define MAX_DNS_LEN 512
#define MAX_DOMAIN_SEC_SIZE 64


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

#endif //PCH_H
