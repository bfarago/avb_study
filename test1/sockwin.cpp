#include "SockWin.h"

#ifdef SOCK_WINSOCK_ENABLE
#include <winsock2.h>
#include <Ws2tcpip.h>
// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")
#endif //SOCK_WINSOCK_ENABLE

#include "stdio.h"

SockWin::SockWin()
{
}


SockWin::~SockWin()
{
}

void SockWin::test1() {
#ifdef SOCK_WINSOCK_ENABLE
	int iResult;
	WSADATA wsaData;

	SOCKET SendSocket = INVALID_SOCKET;
	sockaddr_in RecvAddr;
	struct ethhdr *eth;
	BOOL bOptVal = FALSE;
	int bOptLen = sizeof(BOOL);

	int iOptVal = 0;
	int iOptLen = sizeof(int);

	unsigned short Port = 27015;

	char SendBuf[1024];
	int BufLen = 1024;

	//----------------------
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %d\n", iResult);
		return 1;
	}
#define IPROTO_1722 IPPROTO_RAW
	//---------------------------------------------
	// Create a socket for sending data
	SendSocket = socket(AF_INET, SOCK_RAW, IPROTO_1722);
	if (SendSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	bOptVal = TRUE;
	/* socket options, tell the kernel we provide the IP structure */
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (char *)&bOptVal, bOptLen) < 0)
	{
		wprintf(L"setsockopt() for IP_HDRINCL error");
		exit(1);
	}


	iResult = setsockopt(SendSocket, SOL_SOCKET, SO_BROADCAST, (char *)&bOptVal, bOptLen);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"setsockopt for SO_KEEPALIVE failed with error: %u\n", WSAGetLastError());
	}
	else
		wprintf(L"Set SO_KEEPALIVE: ON\n");
	//---------------------------------------------
	// Set up the RecvAddr structure with the IP address of
	// the receiver (in this example case "192.168.1.1")
	// and the specified port number.
	/*RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(Port);
	RecvAddr.sin_addr.s_addr = inet_addr("192.168.1.1");*/
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_addr.s_addr = 0;

	//---------------------------------------------
	// Send a datagram to the receiver
	wprintf(L"Sending a datagram to the receiver...\n");
	iResult = sendto(SendSocket,
		SendBuf, BufLen, 0, (SOCKADDR *)& RecvAddr, sizeof(RecvAddr));
	if (iResult == SOCKET_ERROR) {
		wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
		closesocket(SendSocket);
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// When the application is finished sending, close the socket.
	wprintf(L"Finished sending. Closing socket.\n");
	iResult = closesocket(SendSocket);
	if (iResult == SOCKET_ERROR) {
		wprintf(L"closesocket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}
	//---------------------------------------------
	// Clean up and quit.
	wprintf(L"Exiting.\n");
	WSACleanup();
#endif //SOCK_WINSOCK_ENABLE
}