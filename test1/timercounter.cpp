#include "timercounter.h"



TimerCounter::TimerCounter()
{
}


TimerCounter::~TimerCounter()
{
}

void TimerCounter::Reset()
{
	Time = Timeout;
}

void TimerCounter::Fire()
{
	Time = 0;
}

bool TimerCounter::ProcessElapsed(int deltaStep)
{
	Time -= deltaStep;
	if (Time <= 0) {
		Time = Timeout;
		return true;
	}
	return false;
}

void TimerCounter::SetTimeout(int maxStep)
{
	//garantee of the new period, if possible
	Time += (maxStep - Timeout);
	if (Time < 0) Time = 0;
	if (Time > maxStep) Time = maxStep;
	//set new period
	Timeout = maxStep;
}
