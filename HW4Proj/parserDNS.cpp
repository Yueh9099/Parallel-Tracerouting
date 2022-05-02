#include "pch.h"
#include "parserDNS.h"
using namespace std;

ParserDNS::ParserDNS(char* buf_in, int resBytes_in, char* sendPkt) {
    buf = buf_in;
    recvBytes = resBytes_in;
    dhRes = (FixedDNSHeader*)buf;
    dh = (FixedDNSHeader*)sendPkt;
}

bool ParserDNS::checkPkt() {
    //check packet size bigger than DNS header
    if (recvBytes < sizeof(FixedDNSHeader)) {
        //printf("\t++ Invalid reply: packet smaller than fixed DNS Header\n");
        return false;
    }
    /*
    printf("\tTXID 0x%04x flags 0x%04x questions %d answers %d authority %d additional %d\n",
        htons(dhRes->ID),
        htons(dhRes->flags),
        htons(dhRes->questions),
        htons(dhRes->answers),
        htons(dhRes->authority),
        htons(dhRes->additional));
    */

    // Check for valid ID
    if (dhRes->ID != dh->ID) {
        //printf("\t++ invalid reply: TXID mismatch, sent 0x%04x, received 0x%04x\n", htons(dh->ID), htons(dhRes->ID));
        return false;
    }

    // Check Rcode
    int Rcode = htons(dhRes->flags) & 0X000f;
    if ((Rcode) == 0) {
        //printf("\tsucceeded with Rcode = %d\n", Rcode);
    }
    else {
        //printf("\tfailed with Rcode = %d\n", Rcode);
        return false;
    }


    return true;
}


bool ParserDNS::printQuestions() {
    if (htons(dhRes->questions) < 0) {
        return false;
    }

    resPacket = (char*)(dhRes + 1);

    //printf("\t------------ [questions] ----------\n");
    for (int i = 0; i < htons(dhRes->questions); i++) {
        if (resPacket - buf >= recvBytes) {
            //printf("\t++ Invalid section: not enough records\n");
            return false;
        }
        string domainName = decodeStrDNS(resPacket);
        if (domainName.empty()) {
            return false;
        }
        //printf("\t\t%s ", domainName.c_str());

        QueryHeader* qhTemp = (QueryHeader*)resPacket;
        //printf("type %d class %d\n", htons(qhTemp->qType), htons(qhTemp->qClass));
        resPacket += sizeof(QueryHeader);
    }
    return true;
}

bool ParserDNS::printAnswers() {
    if (htons(dhRes->answers) > 0) {
        printf("\t------------ [answers] ------------\n");
        return printRR(htons(dhRes->answers));
    }
    return true;
}

string ParserDNS::getHostName() {
    if (!checkPkt()) {
        return "";
    }
    if (!printQuestions()) {
        return "";
    }
    if (htons(dhRes->answers) > 0) {
        //printf("\t------------ [answers] ------------\n");
        return getRR(htons(dhRes->answers));
    }
    return "";
}
// get RR with DNS_PTR type 
string ParserDNS::getRR(int number) {
    for (int i = 0; i < number; i++) {
        if (resPacket - buf >= recvBytes) {
            //printf("\t++ Invalid section: not enough records\n");
            return "";
        }
        if (resPacket + sizeof(DNSanswerHdr) - buf > recvBytes) {
            //printf("\t++ Invalid record: truncated RR answer header\n");
            return "";
        }
        string name = decodeStrDNS(resPacket);
        if (name.empty()) {
            return "";
        }
       //printf("\t\t%s ", name.c_str());
        DNSanswerHdr* dah = (DNSanswerHdr*)resPacket;
        resPacket += sizeof(DNSanswerHdr);
        int qType = (int)htons(dah->qType);
        if (qType == DNS_A) {
            printf("A ");
            if (resPacket + (int)htons(dah->len) - buf > recvBytes) {
                //printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                return "";
            }
            resPacket += 4;
        }
        else if (qType == DNS_PTR || qType == DNS_NS || qType == DNS_CNAME) {
            if (resPacket + (int)htons(dah->len) - buf > recvBytes) {
                //printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                return "";
            }
            string name = decodeStrDNS(resPacket);
            if (name.empty()) {
                return "";
            }
            //printf("%s ", name.c_str());
            if (qType == DNS_PTR) {
                return name;
            }
            
        }

    }
    return "";
}





bool ParserDNS::printRR(int number) {
    for (int i = 0; i < number; i++) {
        if (resPacket - buf >= recvBytes) {
            printf("\t++ Invalid section: not enough records\n");
            return false;
        }
        if (resPacket + sizeof(DNSanswerHdr) - buf > recvBytes) {
            printf("\t++ Invalid record: truncated RR answer header\n");
            return false;
        }
        string name = decodeStrDNS(resPacket);
        if (name.empty()) {
            return false;
        }
        printf("\t\t%s ", name.c_str());
        DNSanswerHdr* dah = (DNSanswerHdr*)resPacket;
        resPacket += sizeof(DNSanswerHdr);
        int qType = (int)htons(dah->qType);
        if (qType == DNS_A) {
            printf("A ");

            if (resPacket + (int)htons(dah->len) - buf > recvBytes) {
                printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");
                return false;
            }

            printf("%d.%d.%d.%d", resPacket[0], resPacket[1], resPacket[2], resPacket[3]);
            

            printf(" TTL = %d\n", htonl(dah->TTL));
            resPacket += 4;
        }
        else if (qType == DNS_PTR || qType == DNS_NS || qType == DNS_CNAME) {
            

            if (resPacket + (int)htons(dah->len) - buf > recvBytes) {
                printf("\n\t++ Invalid record: RR value length stretches the answer beyond the packet\n");

                return false;
            }
            string name = decodeStrDNS(resPacket);
            if (name.empty()) {
                return false;
            }
            printf("%s ", name.c_str());
            printf("TTL = %d\n", htonl(dah->TTL));
        }

    }
    return true;
}



string ParserDNS::decodeStrDNS(char* curPkt) {
    string result;
    int domainSectionSize;
    while ((domainSectionSize = *curPkt) != 0) {

        if ((unsigned char)(*curPkt) >= 0xC0) {
            if (curPkt + 1 - buf >= recvBytes) {
                printf("\n\t++ Invalid record: truncated jump offset\n");
                return "";
            }
            int offset = (((unsigned char)(*curPkt) & 0x3F) << 8) + (unsigned char)curPkt[1];
            if (offset < sizeof(FixedDNSHeader)) {
                printf("\t++ Invalid record: jump into fixed DNS header\n");
                return "";
            }
            if (offset > recvBytes) {

                printf("\t++ Invalid record: jump beyond packet boundary\n");
                return "";
            }
            if ((*(unsigned char*)(buf + offset)) >= 0XC0) {
                printf("\n\t++ Invalid record: jump loop\n");
                return "";
            }

            string temp = decodeStrDNS(buf + offset);
            if (temp.empty()) {
                return "";
            }
            result += temp;
            resPacket = curPkt + 2;
            return result;
        }



        if (domainSectionSize + curPkt - buf > recvBytes) {
            printf("\t++ Invalid record: truncated name\n");
            return "";
        }
        if (domainSectionSize >= MAX_DOMAIN_SEC_SIZE) {
            return "";
        }

        curPkt++;
        char* temp = new char[MAX_DOMAIN_SEC_SIZE];

        memcpy(temp, curPkt, domainSectionSize);

        temp[domainSectionSize] = '\0';
        //printf("temp is : %s\n", temp);
        result += temp;
        curPkt += domainSectionSize;
        if (*curPkt != 0) {
            result += ".";
        }


        delete[] temp;
    }
    resPacket = curPkt + 1;
    return result;
}