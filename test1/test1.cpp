// test1.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include "std_types.h"
#include "sockif.h"
#include "ethif.h"
#include "avdecc.h"

#ifdef WINDOWS
#include "windows.h"
#else
	
#endif


EthIf g_Eth;
AVDECC g_Avdecc;

int main()
{
	printf("Init.\n");
	int tsDelta = 100;
	// int ts = 0;
	g_Eth.Init();
	g_Avdecc.Init();
	g_Avdecc.SetLinkUp(0, true); //set interface and state 
	//todo check if dev open was successfull
	printf("Started.\n");
	while (1) {
		Sleep(tsDelta);
		// ts+=tsDelta;
		g_Avdecc.Schedule(tsDelta);
		g_Eth.MainFunctionRx();
	}
	
	return 0;
}

