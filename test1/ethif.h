#pragma once
#include <pcap.h>
#include "eth2.h"

#pragma pack(push,1)

#pragma pack(pop)
class EthRxIf {
public:
	virtual int rcvpacket(const struct pcap_pkthdr *header, const pkt_eth2_header_p ptr) = 0;
};

class EthDev { 
public:
	pcap_t * fp;
	EthDev();
	int sendpacket(const u_char *, int);
	int rcvpacket(const struct pcap_pkthdr *header, const u_char *pkt_data);
	EthRxIf* rx1722;
	EthRxIf* rxPTP;
	EthRxIf* rxSRP;
};

class EthIf
{
public:
	EthIf();
	~EthIf();
	static EthIf* GetInstance() { return pInstance; }
	// The function checks for new received frames and issues reception indications in polling mode.
	void MainFunctionRx();
	// The function issues transmission confirmations in polling mode. It checks also for transceiver state changes.
	void MainFunctionTx();
	// The function is polling different communication hardware (Ethernet transceiver, Ethernet switch ports) related information, e.g. link state, signal quality. 
	void MainFunctionState();
	void Init();
	EthDev* GetHdl(int devId) { return &devs[devId]; }
	const UCHAR* GetLocalMAC();
private:
	EthDev devs[ETHIF_MAXDEV];
	static EthIf* pInstance;
};

