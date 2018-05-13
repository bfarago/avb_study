#pragma once

class TimerCounter
{
public:
	TimerCounter();
	~TimerCounter();
	void Reset();
	void Fire();
	bool ProcessElapsed(int deltaStep);
	void SetTimeout(int maxStep);
private:
	int Timeout;
	int Time;
};

