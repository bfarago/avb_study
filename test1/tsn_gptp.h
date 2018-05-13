#pragma once
#include "std_types.h"
#include "eth2.h"

#pragma pack(push,1)

typedef enum {
	PTP_MSGTYPE_SYNC = 0,			// Grandmaster starts sync
	PTP_MSGTYPE_PDELAY_REQ = 2,		// initiates the peer delay measurement sequence
	PTP_MSGTYPE_PDELAY_RESP = 3,	// peer delay response
	PTP_MSGTYPE_FOLLOW_UP = 8,		// Grandmaster follow-up
	PTP_MSGTYPE_PDELAY_RESP_FOLLOW_UP = 0x0a, // 
	PTP_MSGTYPE_ANNOUNCE = 0x0b		// Grandmaster capable device
} gptp_msgtype_en;

typedef struct GPTP_Correction_s {

} GPTP_Correction_t;
typedef struct GPTP_SourcePortIdentify_s {

} GPTP_SourcePortIdentify_t;

//IEEE 802.1AS: Timing and Synchronization for Time-Sensitive Applications (gPTP)
typedef struct pkt_802_1AS_s
{
	pkt_eth2_header_t eth;
	UINT16 PtpVersion : 4;
	UINT16 Reserved_0 : 4;
	UINT16 MessageType : 4;
	UINT16 TpSpec : 4;
	UINT16 MessageLength;
	UINT16 Reserved_1 : 8;
	UINT16 DomainNumber : 8;
	UINT16 Flags;
	GPTP_Correction_t Correction;
	UINT32 Reserved_2;
	GPTP_SourcePortIdentify_t SourcePortIdentify;
	UINT16 SequenceId;
	UINT16 LogMessageInterval : 8;
	UINT16 ControlField : 8;
} pkt_802_1AS_t, *pkt_802_1AS_p;

#pragma pack(pop)
