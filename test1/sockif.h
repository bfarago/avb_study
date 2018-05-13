#pragma once
#include "sockcfg.h"

class SockIF
{
public:
	SockIF();
	~SockIF();
	virtual void test1() = 0;
};


#ifdef SOCK_WINSOCK_ENABLE
#include "sockwin.h"
#endif

#ifdef SOCK_PCAP_ENABLE
#include "sockpcap.h"
#endif
