#include "avdecc.h"
#include "sockpcap.h"
#include <stdlib.h>
#include <stdio.h>
#include "ethif.h"
#include <pcap.h>

#ifdef WINDOWS
//#include "windows.h"
#else
#include "string.h"
#include <arpa/inet.h>
#include <endian.h>
#define htonll(x) htobe64(x)
#define ntohll(x) be64toh(x)
#endif
/*
Known limitations:
	- only one eth dev port is used.
*/

unsigned char glob_dest_addr[] = { 0x91, 0xE0, 0xF0, 0x00, 0x0E, 0x80 };
unsigned char glob_1722_addr[] = { 0x91, 0xE0, 0xF0, 0x01, 0x00, 0x00 };
unsigned char glob_802_1AS_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E }; //01-80-C2-00-00-0E
unsigned char glob_srp_addr[] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x20 }; //01-80-C2-00-00-20
unsigned char mc1_dest_addr[] = { 0x00, 0x22, 0x97, 0x80, 0x0D, 0xF2 };

#pragma pack(push,1)

typedef union entity_capabilities {
	UINT32 w;
	UINT8 b[4];
	entity_capabilities_flags_t flags;
} entity_capabilities_t;

typedef union talker_capabilities {
	UINT16 w;
	UINT8 b[2];
	talker_capabilities_flags_t flags;
} talker_capabilities_t;

typedef union listener_capabilities {
	UINT16 w;
	UINT8 b[2];
	talker_capabilities_flags_t flags;
} listener_capabilities_t;

typedef union controller_capabilities {
	UINT32 w;
	UINT8 b[4];
	controller_capabilities_flags_t flags;
} controller_capabilities_t;

typedef enum {
	AVDECC_SUBTYPE_ADP  = 0xfa,	// Avdecc Discovery Protocol (ADP)
	AVDECC_SUBTYPE_AECP = 0xfb,	// AVDECC Enumeration an Control Protocol (AECP)
	AVDECC_SUBTYPE_ACMP = 0xfc,	// AVDECC Connection Management Protocol(ACMP)
	AVDECC_SUBTYPE_MAAP = 0xfe	// AVDECC Multicast Allocation A Protocol(MAAP)
} avdecc_subtype_en;

typedef enum {
	AVDECC_ADP_MSGTYPE_ENTITY_AVAILABLE = 0, // Avdecc Discovery Protocol Entity Available
	AVDECC_ADP_MSGTYPE_ENTITY_DEPARTING = 1, // Avdecc Discovery Protocol Entity Departing to indicate that the entity is now not in operation and will soon be removed from the system
	AVDECC_ADP_MSGTYPE_ENTITY_DISCOVER = 2,	 // Entity Discover to trigger other entities(all entities when the requested entity id is 0 or the specific entity
											 // requested in the entity id) in the network to readvertise themselves with the Entity Available command.
} avdecc_adp_msgtype_en;

typedef enum {
	AVDECC_AECP_AEM_COMMAND = 0, // Avdecc Entity Management Command
	AVDECC_AECP_AEM_RESPONSE = 1, // Avdecc Entity Management Response
} avdecc_aecp_msgtype_en;

typedef enum {
	AECP_AEM_CMD_ACQUIRE_ENTITY = 0,
	AECP_AEM_CMD_LOCK_ENTITY = 1,
	AECP_AEM_CMD_ENTITY_AVAILABLE = 2,
	AECP_AEM_CMD_CONTROLLER_AVAILABLE = 3,
	AECP_AEM_CMD_READ_DESCRIPTOR = 4,
	AECP_AEM_CMD_WRITE_DESCRIPTOR = 5,
	AECP_AEM_CMD_SET_CONFIGURATION = 6,
	AECP_AEM_CMD_GET_CONFIGURATION = 7,
	AECP_AEM_CMD_SET_STREAM_FORMAT = 8,
	AECP_AEM_CMD_GET_STREAM_FORMAT = 9,
	AECP_AEM_CMD_SET_VIDEO_FORMAT = 10,
	AECP_AEM_CMD_GET_VIDEO_FORMAT = 11,
	AECP_AEM_CMD_SET_SENSOR_FORMAT = 12,
	AECP_AEM_CMD_GET_SENSOR_FORMAT = 13,
	AECP_AEM_CMD_SET_STREAM_INFO = 14,
	AECP_AEM_CMD_GET_STREAM_INFO = 15,
	AECP_AEM_CMD_SET_NAME = 16,
	AECP_AEM_CMD_GET_NAME = 17,
	AECP_AEM_CMD_SET_ASSOCIATION_ID = 18,
	AECP_AEM_CMD_GET_ASSOCIATION_ID = 19,
	AECP_AEM_CMD_SET_SAMPLING_RATE = 20,
	AECP_AEM_CMD_GET_SAMPLING_RATE = 21,
	AECP_AEM_CMD_SET_CLOCK_SOURCE = 22,
	AECP_AEM_CMD_GET_CLOCK_SOURCE = 23,
	AECP_AEM_CMD_SET_CONTROL = 24,
	AECP_AEM_CMD_GET_CONTROL = 25,
	AECP_AEM_CMD_INCREMENT_CONTROL = 26,
	AECP_AEM_CMD_DECREMENT_CONTROL = 27,
	AECP_AEM_CMD_SET_SIGNAL_SELECTOR = 28,
	AECP_AEM_CMD_GET_SIGNAL_SELECTOR = 29,
	AECP_AEM_CMD_SET_MIXER = 30,
	AECP_AEM_CMD_GET_MIXER = 31,
	AECP_AEM_CMD_SET_MATRIX = 32,
	AECP_AEM_CMD_GET_MATRIX = 33,
	AECP_AEM_CMD_START_STREAMING = 34,
	AECP_AEM_CMD_STOP_STREAMING = 35,
	AECP_AEM_CMD_REGISTER_UNSOLICITED_NOTIFICATION = 36,
	AECP_AEM_CMD_DEREGISTER_UNSOLICITED_NOTIFICATION = 37,
	AECP_AEM_CMD_IDENTIFY_NOTIFICATION = 38,
	AECP_AEM_CMD_GET_AVB_INFO = 39,
	AECP_AEM_CMD_GET_AS_PATH = 40,
	AECP_AEM_CMD_GET_COUNTERS = 41,
	AECP_AEM_CMD_REBOOT = 42,
	AECP_AEM_CMD_GET_AUDIO_MAP = 43,
	AECP_AEM_CMD_ADD_AUDIO_MAPPINGS = 44,
	AECP_AEM_CMD_REMOVE_AUDIO_MAPPINGS = 45,
	AECP_AEM_CMD_GET_VIDEO_MAP = 46,
	AECP_AEM_CMD_ADD_VIDEO_MAPPINGS = 47,
	AECP_AEM_CMD_REMOVE_VIDEO_MAPPINGS = 48,
	AECP_AEM_CMD_GET_SENSOR_MAP = 49,
	AECP_AEM_CMD_ADD_SENSOR_MAPPINGS = 50,
	AECP_AEM_CMD_REMOVE_SENSOR_MAPPINGS = 51,
	AECP_AEM_CMD_START_OPERATION = 52,
	AECP_AEM_CMD_ABORT_OPERATION = 53,
	AECP_AEM_CMD_OPERATION_STATUS = 54,
	AECP_AEM_CMD_AUTH_ADD_KEY = 55,
	AECP_AEM_CMD_AUTH_DELETE_KEY = 56,
	AECP_AEM_CMD_AUTH_GET_KEY_COUNT = 57,
	AECP_AEM_CMD_AUTH_GET_KEY = 58,
	AECP_AEM_CMD_AUTHENTICATE = 59,
	AECP_AEM_CMD_DEAUTHENTICATE = 60
} avdecc_aecp_aem_cmdtype_en;

/** The result status of the AEM command in the response field */
typedef enum {
	AECP_AEM_STATUS_SUCCESS = 0, /**< The AVDECC Entity successfully performed the command and has valid results. */
	AECP_AEM_STATUS_NOT_IMPLEMENTED = 1, /**< The AVDECC Entity does not support the command type. */
	AECP_AEM_STATUS_NO_SUCH_DESCRIPTOR = 2, /**< A descriptor with the descriptor_type and descriptor_index specified does not exist. */
	AECP_AEM_STATUS_ENTITY_LOCKED = 3, /**< The AVDECC Entity has been locked by another AVDECC Controller. */
	AECP_AEM_STATUS_ENTITY_ACQUIRED = 4, /**< The AVDECC Entity has been acquired by another AVDECC Controller. */
	AECP_AEM_STATUS_NOT_AUTHENTICATED = 5, /**< The AVDECC Controller is not authenticated with the AVDECC Entity. */
	AECP_AEM_STATUS_AUTHENTICATION_DISABLED = 6, /**< The AVDECC Controller is trying to use an authentication command when authentication isn’t enable on the AVDECC Entity. */
	AECP_AEM_STATUS_BAD_ARGUMENTS = 7, /**< One or more of the values in the fields of the frame were deemed to be bad by the AVDECC Entity (unsupported, incorrect combination, etc). */
	AECP_AEM_STATUS_NO_RESOURCES = 8, /**< The AVDECC Entity cannot complete the command because it does not have the resources to support it. */
	AECP_AEM_STATUS_IN_PROGRESS = 9, /**< The AVDECC Entity is processing the command and will send a second response at a later time with the result of the command. */
	AECP_AEM_STATUS_ENTITY_MISBEHAVING = 10, /**< The AVDECC Entity is generated an internal error while trying to process the command. */
	AECP_AEM_STATUS_NOT_SUPPORTED = 11, /**< The command is implemented but the target of the command is not supported. For example trying to set the value of a read-only Control. */
	AECP_AEM_STATUS_STREAM_IS_RUNNING = 12, /**< The Stream is currently streaming and the command is one which cannot be executed on an Active Stream. */
} avdecc__aecp_aem_status_code_en;

typedef enum {
	AVDECC_AECP_AEM_DTYPE_ = 0, // 
	AVDECC_AECP_AEM_DTYPE_STREAM_OUTPUT = 6, // 
} avdecc_aecp_aem_descriptortype_en;

typedef union {
	UINT8 w;
	//UINT8 b[1];
	//avdecc_subtype_en code;
} avdecc_subtype_t;

//IEEE Std 1722.1: AVB Discovery, Enumeration, Connection management and Control(AVDECC)
typedef struct pkt_1722
{
	pkt_eth2_header_t eth;
	avdecc_subtype_t subtype;

	UCHAR MessageType : 4;
	UCHAR AvtpStreamIdValid : 1; // 0
	UCHAR AvtpVersion : 3;

	UCHAR ControlDataLengthHi : 3;
	UCHAR ValidTime : 5; // in 2 sec increments
	UCHAR ControlDataLengthLo;
	ULONG64 EntityId;
	ULONG64 EntityModelId;
	entity_capabilities_t EntityCapabilities;
	UINT16 TalkerStreamSources;
	talker_capabilities_t TalkerCapabilities;
	UINT16 ListenerStreamSinks;
	listener_capabilities_t ListenerCapabilities;
	controller_capabilities_t ControllerCapabilities;
	UINT32 AvailableIndex;
	ULONG64 GrandmasterId; //gPTP
	UINT32 GPtpDomainNo:8;
	UINT32 Reserved_0 : 24;
	UINT16 IdentifyControlIndex;
	UINT16 InterfaceIndex;
	ULONG64 AssociationId;
	ULONG32 Reserved_1; //Reserved
} pkt_1722_t, *pkt_1722_p;

//Aecp data unit
typedef struct {
	UINT32 ControllerEntityId;
	UINT32 Reserved_0 : 16;
	UINT32 SequenceId : 16;
	UINT32 Payload[1];
} aecp_data_s;

#pragma pack(pop)


AVDECC::AVDECC()
{
}


AVDECC::~AVDECC()
{
}

pkt_1722_t pkt_AVDECCAdpAvailable;
void AVDECC::Init()
{
	EthIf* pEth = EthIf::GetInstance();
	availIndx = 0;
	pkt_1722_t &pkt = pkt_AVDECCAdpAvailable;
	memset(&pkt_AVDECCAdpAvailable, 0, sizeof(pkt_1722_t));
	memcpy(pkt.eth.source, pEth->GetLocalMAC(), ETH_ALEN);
	memcpy(pkt.eth.dest, glob_1722_addr, ETH_ALEN);
	pkt.eth.type = ETH_TYPE_1722_1; //1722.1
	pkt.subtype.w = AVDECC_SUBTYPE_ADP; //discovery
	pkt.MessageType = AVDECC_ADP_MSGTYPE_ENTITY_AVAILABLE;  //ENTITY_AVAILABLE

	pkt.ValidTime = AVDECC_ADP_ANN_DEFAULT_VALIDTIME;
	pkt.ControlDataLengthHi = 0;
	pkt.ControlDataLengthLo = 56; // based on standard

	data.Changed.w = 0;
	data.EntityId= AVDECC_ADP_ANN_DEFAULT_ENTITYID; data.Changed.f.EntityId = 1;
	data.ModelId = AVDECC_ADP_ANN_DEFAULT_MODELID; data.Changed.f.ModelId = 1;
	data.GrandmasterId = 0; data.Changed.f.GrandmasterId = 1;
	data.GPtpDomainNo = 0;  data.Changed.f.GPtpDomainNo = 1;
	data.AssociationId = 0; data.Changed.f.AssociationId = 1;
	data.IdentifyControlIndex = 0;  data.Changed.f.IdentifyControlIndex = 1;
	data.InterfaceIndex = 0;  data.Changed.f.InterfaceIndex = 1;

	reannounceTimer.SetTimeout(AVDECC_ADP_ANN_DEFAULT_VALIDTIME* AVDECC_ADP_VALIDTIME_INCREMENT - AVDECC_ADP_VALIDTIME_ADDITIONAL_TIME); //n*2 sec in ms
	needsAdvertise = true;
	wasAdvertised = false;
	needsDepart = false;
	wasLinkUp = false;
	devId = 0; isLinkUp = false; //do not use dev by default
}
void AVDECC::PrepareAdp(void *ptr) {
	if (data.Changed.w) {
		pkt_1722_t *pkt = (pkt_1722_t *)ptr;
		if (data.Changed.f.EntityId) {
			pkt->EntityId = htonll(data.EntityId);
			data.Changed.f.EntityId = 0;
		}
		if (data.Changed.f.ModelId) {
			pkt->EntityModelId = htonll(data.ModelId);
			data.Changed.f.ModelId = 0;
		}
		if (data.Changed.f.EntityCapabilities) {
			pkt->EntityCapabilities.flags.EfuMode = 1;
			pkt->EntityCapabilities.flags.AddressAccess = 1;
			pkt->EntityCapabilities.flags.AEM = 1;
			pkt->EntityCapabilities.flags.ClassA = 1;
			pkt->EntityCapabilities.flags.gPtpSupported = 1;
			pkt->EntityCapabilities.w = htonl(pkt->EntityCapabilities.w);
			data.Changed.f.EntityCapabilities = 0;
		}

		if (data.Changed.f.TalkerStreamSources) {
			pkt->TalkerStreamSources = htons(data.TalkerStreamSources);
			pkt->TalkerCapabilities.flags.Implemented = 1;
			pkt->TalkerCapabilities.flags.Audio = 1;
			//pkt->TalkerCapabilities.flags.MediaClock = 1;
			pkt->TalkerCapabilities.w = htons(pkt->TalkerCapabilities.w);
			data.Changed.f.TalkerStreamSources = 0;
		}
		if (data.Changed.f.ListenerStreamSinks) {
			pkt->ListenerStreamSinks = htons(data.ListenerStreamSinks);
			pkt->ListenerCapabilities.flags.Implemented = 0;
			pkt->ListenerCapabilities.w = htons(pkt->ListenerCapabilities.w);
			data.Changed.f.ListenerStreamSinks = 0;
		}
		if (data.Changed.f.ControllerCapabilities) {
			pkt->ControllerCapabilities.flags.Implemented = 0;
			pkt->ControllerCapabilities.w = htonl(pkt->ControllerCapabilities.w);
			data.Changed.f.ControllerCapabilities = 0;
		}

		if (data.Changed.f.GrandmasterId) {
			pkt->GrandmasterId = htonll(data.GrandmasterId);
			data.Changed.f.GrandmasterId = 0;
		}
		if (data.Changed.f.GPtpDomainNo) {
			pkt->GPtpDomainNo = data.GPtpDomainNo;
			data.Changed.f.GPtpDomainNo = 0;
		}
		if (data.Changed.f.IdentifyControlIndex) {
			pkt->IdentifyControlIndex = htons(data.IdentifyControlIndex);
			data.Changed.f.IdentifyControlIndex = 0;
		}
		if (data.Changed.f.InterfaceIndex) {
			pkt->InterfaceIndex = htons(data.InterfaceIndex);
			data.Changed.f.InterfaceIndex = 0;
		}
		if (data.Changed.f.AssociationId) {
			pkt->AssociationId = htonll(data.AssociationId);
			data.Changed.f.AssociationId = 0;
		}
	}
}
void AVDECC::ProcessAdp(AvdeccData * pData, void * ptr)
{
	// convert network endian to host service endian, get the internal data from network protocol data.
	pkt_1722_t* p = (pkt_1722_t*)ptr;
	pData->EntityId = ntohll(p->EntityId);
	pData->ModelId = ntohll(p->EntityModelId);
	pData->GrandmasterId = ntohll(p->GrandmasterId);
	pData->AssociationId = ntohll(p->AssociationId);
	pData->TalkerStreamSources = ntohs(p->TalkerStreamSources);
	pData->ListenerStreamSinks = ntohs(p->ListenerStreamSinks);
	pData->IdentifyControlIndex = ntohs(p->IdentifyControlIndex);
	pData->InterfaceIndex = ntohs(p->InterfaceIndex);
	pData->GPtpDomainNo = p->GPtpDomainNo;
	p->EntityCapabilities.w = htonl(p->EntityCapabilities.w);
	p->TalkerCapabilities.w = htons(p->TalkerCapabilities.w);
	p->ListenerCapabilities.w = htons(p->ListenerCapabilities.w);
	p->ControllerCapabilities.w = htonl(p->ControllerCapabilities.w);
	pData->EntityCapabilities = p->EntityCapabilities.flags;
	pData->TalkerCapabilities = p->TalkerCapabilities.flags;
	pData->ListenerCapabilities = p->ListenerCapabilities.flags;
	pData->ControllerCapabilities = p->ControllerCapabilities.flags;
}
int AVDECC::rcvpacket(const struct pcap_pkthdr *header, const pkt_eth2_header_p ptr) {
	EthIf* pEth = EthIf::GetInstance();
	pkt_1722_t* p = (pkt_1722_t*)ptr;
	AvdeccData* pData = &endpoints[endpointsnum];
	bool hit = false;
	int id = endpointsnum;
	if (AVDECC_SUBTYPE_ADP != p->subtype.w) {
		return 1;
	}
	UINT64 entityId = ntohll(p->EntityId);
	switch (p->MessageType) {
	case AVDECC_ADP_MSGTYPE_ENTITY_AVAILABLE:
	case AVDECC_ADP_MSGTYPE_ENTITY_DEPARTING:
		for (int i = 0; i < endpointsnum; i++) {
			if (endpoints[i].EntityId == entityId) {
				pData = &endpoints[i];
				hit = true;
				id = i;
				break;
			}
		}
		
		break;
	case AVDECC_ADP_MSGTYPE_ENTITY_DISCOVER:
		/*
		if (!memcmp(p->eth.dest, pEth->GetLocalMAC(), ETH_ALEN))) {
		//Do
		}
		*/
		
		break;
	}
	ProcessAdp(pData, p); //reverse. big endian to little

	epTimer[id].SetTimeout(p->ValidTime * AVDECC_ADP_VALIDTIME_INCREMENT + AVDECC_ADP_VALIDTIME_ADDITIONAL_TIME);
	epTimer[id].Reset();
	switch(p->MessageType){
		case AVDECC_ADP_MSGTYPE_ENTITY_DEPARTING:
			endpoints[id].Valid = false;
			epTimer[id].Fire();
			printf("DEPART %016llx: \n", pData->EntityId);
		break;
		case AVDECC_ADP_MSGTYPE_ENTITY_AVAILABLE:
			endpoints[id].Valid = true;
			if (hit)
			{
				for (int i = 0; i < endpointsnum; i++) {
					printf("%02i %c %i %i |", epTimer[i].GetTime()/1000, endpoints[i].Valid?'V':'-', endpoints[i].TalkerStreamSources, endpoints[i].ListenerStreamSinks);
				}
				printf("AVAILABLE %016llx: \n", pData->EntityId);
			}
			else
				printf("AVAILABLE %016llx: (NEW)\n", pData->EntityId);
		break;
		case AVDECC_ADP_MSGTYPE_ENTITY_DISCOVER:
			printf("DISCOVER %016llx: \n", pData->EntityId);
		break;
	}
	
	if (!hit) {
		if (endpointsnum < AVDECC_MAX_ENDPOINTS) {
			endpointsnum++;
		}
	}
	return 0;
}
int AVDECC::SendAdpAvailable()
{
	int res = 0;
	wasLinkUp = isLinkUp;
	if (needsAdvertise && isLinkUp)
	{
		EthIf* pEth = EthIf::GetInstance();
		EthDev* pEthDev = pEth->GetHdl(devId);
		pkt_1722_t &pkt = pkt_AVDECCAdpAvailable;
		pkt.MessageType = AVDECC_ADP_MSGTYPE_ENTITY_AVAILABLE;  //ENTITY_AVAILABLE
		PrepareAdp(&pkt);
		availIndx++;
		pkt.AvailableIndex = htonl(availIndx);

		const u_char* packet = (u_char*)&pkt;
		res = pEthDev->sendpacket(packet, sizeof(pkt));
		data.Changed.w = 0;
		wasAdvertised = true;
	}
	return res;
}
int AVDECC::SendAdpDepart()
{
	int res = 0;
	EthIf* pEth = EthIf::GetInstance();
	EthDev* pEthDev = pEth->GetHdl(0);
	pkt_1722_t &pkt = pkt_AVDECCAdpAvailable;
	pkt.MessageType = AVDECC_ADP_MSGTYPE_ENTITY_DEPARTING;
	PrepareAdp(&pkt);
	const u_char* packet = (u_char*)&pkt;
	res = pEthDev->sendpacket(packet, sizeof(pkt));
	
	wasAdvertised = false;
	needsDepart = false;
	return res;
}
int AVDECC::SendAdpDiscover() {
	int res = 0;
	EthIf* pEth = EthIf::GetInstance();
	EthDev* pEthDev = pEth->GetHdl(0);
	pkt_1722_t &pkt = pkt_AVDECCAdpAvailable;
	pkt.MessageType = AVDECC_ADP_MSGTYPE_ENTITY_DISCOVER;
	PrepareAdp(&pkt);
	pkt.EntityId = discoverEntityId;
	const u_char* packet = (u_char*)&pkt;
	res = pEthDev->sendpacket(packet, sizeof(pkt));
	return res;
}
void AVDECC::SetNeedsAdvertise(bool newState)
{
	if (newState != needsAdvertise) {
		if (!newState) {
			//stop advertise
			needsDepart = wasAdvertised;
			//reset timer
			reannounceTimer.Fire();
		}
		needsAdvertise = newState;
	}
}
void AVDECC::SetReannounceTimerTimeout(int ms)
{
	reannounceTimer.SetTimeout(ms);
}
void AVDECC::Schedule(unsigned int deltaTime)
{
	if (needsAdvertise) {
		if (reannounceTimer.ProcessElapsed(deltaTime)) {
			SendAdpAvailable();
		}
	}
	else
	if (needsDepart){
		SendAdpDepart();
	}
	for (int i = 0; i < endpointsnum; i++) {
		if (endpoints[i].Valid) {
			if (epTimer[i].ProcessElapsed(deltaTime)) {
				endpoints[i].Valid = false;
				printf("TIMEOUT %016llx: (INVALIDATED)\n", endpoints[i].EntityId);
			}
		}
	}
}
void AVDECC::SetLinkUp(int aDevId, bool newState)
{
	if (devId != aDevId) {
		//dev. changed
	}
	devId = aDevId;
	if (wasLinkUp != newState) {
		//changed
		wasLinkUp = isLinkUp;
	}
	isLinkUp = newState;
	EthIf* pEth = EthIf::GetInstance();
	EthDev* pEthDev = pEth->GetHdl(0);
	if (pEthDev) {
		if (isLinkUp) {
			pEthDev->rx1722 = this;
			Reannounce();
		}
		else {
			pEthDev->rx1722 = NULL; //TODO: ?
		}
	}
}
void AVDECC::Reannounce()
{
	reannounceTimer.Fire(); //do it as soon as possible
}
void AVDECC::DoAdvertise() {
	SetNeedsAdvertise(true);
}
void AVDECC::DoTerminate() {
	SetNeedsAdvertise(false);
}

void AVDECC::SetGrandmasterId(UINT64 newGrandmasterId)
{
	if (data.GrandmasterId != newGrandmasterId) {
		//changed
		data.GrandmasterId = newGrandmasterId;
		data.Changed.f.GrandmasterId = 1;
		Reannounce();
	}
}

void AVDECC::SetAssociationId(UINT64 newAssociationId)
{
	if (data.AssociationId != newAssociationId) {
		//changed
		data.AssociationId = newAssociationId;
		data.Changed.f.AssociationId = 1;
		Reannounce();
	}
}
