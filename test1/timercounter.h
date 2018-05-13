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
	int GetTime()const { return Time; }
	int GetTimeout()const { return Timeout; }
private:
	int Timeout;
	int Time;
};

