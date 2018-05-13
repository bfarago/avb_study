#pragma once
#include "std_types.h"
#include "timercounter.h"
#include "ethif.h"
#include "avdecc_cfg.h"

#pragma pack(push,1)

typedef struct entity_capabilities_flags {
	UINT32 EfuMode : 1;
	UINT32 AddressAccess : 1;
	UINT32 GatewayEntity : 1;
	UINT32 AEM : 1;
	UINT32 LegacyAvc : 1;
	UINT32 AssociationIdSupported : 1;
	UINT32 AssociationIdValid : 1;
	UINT32 VendorUnique : 1;
	UINT32 ClassA : 1;
	UINT32 ClassB : 1;
	UINT32 gPtpSupported : 1;
	UINT32 AEM_AUTHENTICATION_SUPPORTED : 1;
	UINT32 AEM_AUTHENTICATION_REQUIRED : 1;
	UINT32 AEM_PERSISTENT_ACQUIRE_SUPPORTED : 1;
	UINT32 AEM_IDENTIFY_CONTROL_INDEX_VALID : 1;
	UINT32 AEM_INTERFACE_INDEX_VALID : 1;
	UINT32 GENERAL_CONTROLLER_IGNORE : 1;
	UINT32 ENTITY_NOT_READY : 1;
	UINT32 ACMP_ACQUIRE_WITH_AEM : 1;	//bit13 bigend
	UINT32 ACMP_AUTHENTICATE_WITH_AEM : 1; //bit12
	UINT32 SUPPORTS_UDPV4_AVDECC : 1; //bit11
	UINT32 SUPPORTS_UDPV4_STREAMING : 1; //bit10
	UINT32 SUPPORTS_UDPV6_AVDECC : 1; //bit9
	UINT32 SUPPORTS_UDPV6_STREAMING : 1; //bit8
	UINT32 AEM_INTERFACE_INDEX_IS_TSN : 1; //bit7
	UINT32 MULTIPLE_GPTP_DOMAINS : 1; //bit6
	UINT32 Dummy3 : 6;
}entity_capabilities_flags_t;

typedef struct talker_capabilities_flags {
	UINT16 Implemented : 1;
	UINT16 FastConnect : 1; //bit14 SUPPORTS_FAST_CONNECT
	UINT16 AutoReconnect : 1;

	UINT16 Dummy1 : 6;

	UINT16 Other : 1;
	UINT16 Control : 1;
	UINT16 MediaClock : 1;
	UINT16 Smpte : 1;
	UINT16 Midi : 1;
	UINT16 Audio : 1;
	UINT16 Video : 1;

}talker_capabilities_flags_t;
typedef struct controller_capabilities_flags {
	UINT32 Implemented : 1;
	UINT32 Layer3Proxy : 1;

	UINT32 Dummy1 : 30;
}controller_capabilities_flags_t;

typedef struct AcdeccDataFieldChanged_s {
	int EntityId : 1;
	int ModelId : 1;
	int GrandmasterId : 1;
	int AssociationId : 1;
	int IdentifyControlIndex : 1;
	int InterfaceIndex : 1;
	int GPtpDomainNo : 1;
	int TalkerStreamSources : 1;
	int ListenerStreamSinks : 1;
	int ControllerCapabilities : 1;
	int EntityCapabilities : 1;
} AcdeccDataFieldChanged_st;

typedef union {
	UINT32 w;
	UINT8 b[4];
	AcdeccDataFieldChanged_st f;
}AcdeccDataFieldChanged_t;
#pragma pack(pop)

class AvdeccData {
public:
	UINT64 EntityId;
	UINT64 ModelId;
	UINT64 GrandmasterId;
	UINT64 AssociationId;
	UINT16 TalkerStreamSources;
	UINT16 ListenerStreamSinks;
	UINT16 IdentifyControlIndex;
	UINT16 InterfaceIndex;
	unsigned char GPtpDomainNo;
	bool Valid;
	AcdeccDataFieldChanged_t Changed;
	entity_capabilities_flags_t EntityCapabilities;
	talker_capabilities_flags_t TalkerCapabilities;
	talker_capabilities_flags_t ListenerCapabilities;
	controller_capabilities_flags_t ControllerCapabilities;
};

class AVDECC : public EthRxIf
{
public:
	AVDECC();
	~AVDECC();
	void Init();
	void DoAdvertise();
	void DoTerminate();
	void SetGrandmasterId(UINT64 newGrandmasterId);
	void SetAssociationId(UINT64 newAssociationId);
	void SetNeedsAdvertise(bool newState = true);
	bool GetNeedsAdvertise() const { return needsAdvertise; }
	void SetReannounceTimerTimeout(int ms);
	void Schedule(unsigned int deltaTime);
	void SetLinkUp(int aDevId, bool newState);
	void Reannounce();
	int rcvpacket(const struct pcap_pkthdr *header, const pkt_eth2_header_p ptr);
private:
	void PrepareAdp(void *ptr);
	void ProcessAdp(AvdeccData* pData, void* ptr);
	int SendAdpAvailable();
	int SendAdpDepart();
	int SendAdpDiscover();
	int devId;
	UINT64 discoverEntityId;
	
	TimerCounter reannounceTimer;
	bool needsAdvertise;
	bool wasAdvertised;
	bool needsDepart;
	unsigned short availIndx;
	AvdeccData data;
	AvdeccData endpoints[AVDECC_MAX_ENDPOINTS];
	TimerCounter epTimer[AVDECC_MAX_ENDPOINTS];
	int endpointsnum;
	bool isLinkUp;
	bool wasLinkUp;

	bool rcvdDiscover; // discover msg received before.
	UINT64 rcvdDiscoverEntityId;
};

