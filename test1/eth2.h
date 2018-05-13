#pragma once
#include "std_types.h"

#pragma pack(push,1)
#define ETHIF_MAXDEV (1)
#define ETH_ALEN (6)

#if  (PLATFORM_ENDIAN == BIGENDIAN)
#define ETH_TYPE_1722_1 0x22f0
#define ETH_TYPE_802_1AS 0x88F7
#define ETH_TYPE_SRP 0x22ea
#else
#define ETH_TYPE_1722_1 0xf022
#define ETH_TYPE_802_1AS 0xf788
#define ETH_TYPE_SRP 0xea22
#endif

//Ethernet Header
typedef struct pkt_eth2_header
{
	UCHAR dest[ETH_ALEN]; //Total 48 bits
	UCHAR source[ETH_ALEN]; //Total 48 bits
	USHORT type; //16 bits
} pkt_eth2_header_t, *pkt_eth2_header_p;
#pragma pack(pop)
