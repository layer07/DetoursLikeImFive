#ifndef HELPERFUNCTIONS_H
#define HELPERFUNCTIONS_H

// Include necessary headers
#include "pch.h"

// Function declarations

// Function to initialize the logging thread
void InitializeLogThread();

// Function to send a log message via UDP
void LogMessage(const std::string& message);

// Exported function
extern "C" __declspec(dllexport) void Lain1337();

#endif // HELPERFUNCTIONS_H