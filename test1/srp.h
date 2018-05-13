#pragma once
#include "Std_Types.h"
#include "eth2.h"

#pragma pack(push,1)

typedef enum {
	SRP_TALKER_ADVERTISE = 0,
	SRP_TALKER_FAILED = 1,
	SRP_LISTENER_ADVERTISE = 2,
	SRP_DOMAIN = 3,
} srp_AttributeType_en;

typedef enum {
	SRP_EVENT_NEW = 0,
	SRP_EVENT_JOIN_IN = 1,
	SRP_EVENT_IN = 2,
	SRP_EVENT_JOIN_MT = 3,
	SRP_EVENT_MT = 4,
	SRP_EVENT_LV = 5
} srp_AttributeEvent_en;

typedef enum {
	SRP_LEAVE_ALL_EVENT = 0,
	SRP_LEAVE_ALL = 1,
} srp_LeaveAllEvent_en;

typedef struct VectorAttribute_s {
	UINT16 NumberOfValues : 13;
	UINT16 LeaveAllEvent : 3;
	UINT8 Attr[1]; //dynamic:
				   //UCHAR FirstValue[AttributeLength];
				   //UCHAR PackedEvent[n/3]; // = (Event3 * 6+ Event2)* 6+ Event1
}VectorAttribute_t;
#define SRP_VECTOR_ENDMARK (0x0000U)

//IEEE 802.1Qat: Stream Reservation Protocol (SRP)
typedef struct pkt_SRP
{
	pkt_eth2_header_t eth;
	UINT16 AttributeType : 8;
	UINT16 ProtocolVersion : 8;
	UINT16 AttributeListLength : 8;
	UINT16 AttributeLength : 8;
	UINT16 VectorAttribute : 8;
	UINT16 AttributeListLength2 : 8;
	VectorAttribute_t VectorAttribute[1];
} pkt_SRP_t, *pkt_SRP_p;

//IEEE 802.1Qat: Stream Reservation Protocol (SRP)
typedef struct pkt_AVTP
{
	pkt_eth2_header_t eth;
	UINT32 Tu : 1;
	UINT32 Reserved_0 : 7;
	UINT32 SeqNo : 8;
	UINT32 Tv : 1;
	UINT32 Reserved_1 : 2;
	UINT32 Mr : 1;
	UINT32 Ver : 3;
	UINT32 Sv : 1;
	UINT32 Subtype : 8;
	UINT64 StreamId;
	UINT32 TimeStamp;
	UINT32 BitDepth : 8;
	UINT32 ChannelsPerFrame : 10;
	UINT32 Reserved_2 : 2;
	UINT32 Nsr : 4;
	UINT32 Format : 8;
	UINT32 Reserved_3 : 8;
	UINT32 Evt : 4;
	UINT32 Sp : 1;
	UINT32 Reserved_4 : 3;
	UINT32 StreamDataLength : 16;
	UINT8 StreamDataPayloadp[0];
} pkt_AVTP_t, *pkt_AVTP_p;

#pragma pack(pop)
