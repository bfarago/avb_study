#include "ethif.h"

#ifdef WINDOWS
const char* deviceName = "\\Device\\NPF_{EBD2DB41-B5F2-45EB-A10F-9BFC926CECBA}";  //"rpcap://eth0";
#else
const char* deviceName = "enp1s0"; //"rpcap://enp1s0";
#endif

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
unsigned short csum(unsigned short *buf, int nwords)
{       //
	unsigned long sum;
	for (sum = 0; nwords>0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

EthIf* EthIf::pInstance = NULL;

EthIf::EthIf()
{
	pInstance = this;

}


EthIf::~EthIf()
{
}

/* Callback function invoked by libpcap for every incoming packet */
void Eth_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	EthDev*pDev = (EthDev*)param;
	if (pDev) pDev->rcvpacket(header, pkt_data);
}

// The function checks for new received frames and issues reception indications in polling mode.
void EthIf::MainFunctionRx()
{
	const int id = 0;
	pcap_dispatch(devs[id].fp, 10, Eth_packet_handler, (u_char*)&devs[id]);
}


// The function issues transmission confirmations in polling mode. It checks also for transceiver state changes.
void EthIf::MainFunctionTx()
{
}


// The function is polling different communication hardware (Ethernet transceiver, Ethernet switch ports) related information, e.g. link state, signal quality. 
void EthIf::MainFunctionState()
{
}

void listEthIf()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(//PCAP_SRC_IF_STRING, NULL ,
		&alldevs, errbuf)
		== -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		// exit(1);//todo: unix 
		return;
	}

	/* Print the list */
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}

	/* We don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
}
const unsigned char loc_src_addr[] = { 0x30, 0x85, 0xa9, 0x97, 0x6D, 0x0B };
const UCHAR* EthIf::GetLocalMAC() {
	return loc_src_addr;
}

void EthIf::Init()
{
	listEthIf();
	pcap_t * fp;

	int id = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((fp = pcap_open_live(
		deviceName,		// name of the device
		65536,			// portion of the packet to capture. It doesn't matter in this case 
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		devs[id].fp = 0;
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", deviceName);
		return; // 2;
	}
	devs[id].fp = fp;
	pcap_dispatch(fp, 10, Eth_packet_handler, (u_char*)&devs[id]);
}
EthDev::EthDev() {
	rx1722 = NULL;
	rxPTP = NULL;
	rxSRP = NULL;
}
int EthDev::sendpacket(const u_char * buf, int len)
{
	return pcap_sendpacket(fp, buf, len);
}
int EthDev::rcvpacket(const struct pcap_pkthdr *header, const u_char *pkt_data) {
	pkt_eth2_header_p p = (pkt_eth2_header_p)pkt_data;
	switch (p->type) {
	case ETH_TYPE_1722_1:
		if (rx1722) 	rx1722->rcvpacket(header, p);
		break;
	case ETH_TYPE_802_1AS:
		if (rxPTP) rxPTP->rcvpacket(header, p);
		break;
	case ETH_TYPE_SRP:
		if (rxSRP) 	rxSRP->rcvpacket(header, p);
		break;
	}
	//if (!memcmp(glob_1722_addr, p->dest)){
	//}
	return 0;
}
