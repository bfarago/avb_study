#pragma once

#include "sockif.h"

class SockPcap :
	public SockIF
{
public:
	SockPcap();
	virtual ~SockPcap();
	void test1();
};

