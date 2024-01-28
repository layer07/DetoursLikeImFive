#include "pch.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "detours.h"
#include <iostream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "detours.lib")

void Hexdump(const char* data, int length);

typedef int (WINAPI* ConnectFunction)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WINAPI* SendFunction)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* RecvFunction)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* WSARecvFunction)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

ConnectFunction originalConnect = nullptr;
SendFunction originalSend = nullptr;
RecvFunction originalRecv = nullptr;
WSARecvFunction originalWSARecv = nullptr;

int WINAPI DetouredConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
    sockaddr_in* sa_in = (sockaddr_in*)name;
    int port = ntohs(sa_in->sin_port);
    const char* ipAddress = inet_ntoa(sa_in->sin_addr);

    // Print the IP and port it's trying to connect to
    printf("Connecting to IP: %s, Port: %d\n", ipAddress, port);

    int result = originalConnect(s, name, namelen);

    return result;
}

int WINAPI DetouredSend(SOCKET s, const char* buf, int len, int flags)
{
    // Your custom logic for send here

    Hexdump(buf, len);

    int result = originalSend(s, buf, len, flags);

    return result;
}

int WINAPI DetouredRecv(SOCKET s, char* buf, int len, int flags)
{
    printf("RECV");
    int result = originalRecv(s, buf, len, flags);

    if (result > 0) {
        // Hexdump the received data
        Hexdump(buf, result);
    }

    return result;
}

int WSAAPI DetouredWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    printf("WSARecv - Buffer Count: %u\n", dwBufferCount);

    // Iterate through the lpBuffers array and print the size of each buffer
    for (DWORD i = 0; i < dwBufferCount; i++) {
        printf("Buffer %u Size: %u\n", i, lpBuffers[i].len);
    }

    int result = originalWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    Hexdump(lpBuffers->buf, 256); // You can adjust the size you want to dump here    
    return result;
}

extern "C" __declspec(dllexport) void Lain1337()
{
    // Your custom code here
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (AllocConsole()) {
        freopen("CONOUT$", "w", stdout);
        SetConsoleTitle(L"Injected Console");
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
        std::cout << "This is the injected console!" << std::endl;
    }

    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            return FALSE;
        }

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        originalConnect = (ConnectFunction)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "connect");
        originalSend = (SendFunction)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "send");
        originalRecv = (RecvFunction)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "recv");
        originalWSARecv = (WSARecvFunction)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "WSARecv");

        DetourAttach(&(PVOID&)originalConnect, DetouredConnect);
        DetourAttach(&(PVOID&)originalSend, DetouredSend);
        DetourAttach(&(PVOID&)originalRecv, DetouredRecv);
        DetourAttach(&(PVOID&)originalWSARecv, DetouredWSARecv);

        DetourTransactionCommit();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)originalConnect, DetouredConnect);
        DetourDetach(&(PVOID&)originalSend, DetouredSend);
        DetourDetach(&(PVOID&)originalRecv, DetouredRecv);
        DetourDetach(&(PVOID&)originalWSARecv, DetouredWSARecv);

        DetourTransactionCommit();

        WSACleanup();
    }

    return TRUE;
}

void Hexdump(const char* data, int length)
{
    for (int i = 0; i < length; i += 16)
    {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << i << ": ";

        for (int j = 0; j < 16; ++j)
        {
            if (i + j < length)
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)data[i + j] << " ";
            else
                std::cout << "   ";

            if (j == 7)
                std::cout << "  ";
        }

        std::cout << " ";

        for (int j = 0; j < 16; ++j)
        {
            if (i + j < length)
            {
                char c = data[i + j];
                if (c >= 32 && c <= 126)
                    std::cout << c;
                else
                    std::cout << ".";
            }
            else
            {
                std::cout << " ";
            }
        }

        std::cout << std::endl;
    }
}
