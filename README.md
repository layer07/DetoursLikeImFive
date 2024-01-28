### What is Detours

Microsoft Detours is a powerful binary instrumentation framework developed by Microsoft Research. It is commonly used for ```hooking and intercepting``` functions in Windows applications and has a wide range of uses, including **debugging**, **profiling**, and **creating software patches**. With Detours, developers can redirect function calls to their own code, so it is possible to monitor or modify the behavior of existing software without requiring access to the original source code. This makes it a valuable tool for various software development and analysis tasks, including creating custom APIs, implementing debugging tools, and conducting security research. 


### What for?

We'll be using Detours to hook Windows API calls, for this specific guide, our goal is to intercept and manipulate winsock ```ws2_32.dll```, we won't hook all the exported functions from ```ws2_32.dll```, only a few that are quite importante, such as ```connect```, ```send```, ```recv``` and ```WSARecv```. 


### What do we need?

OK so, the list is not huge, but if you want to start using detours, for this guide you'll need.

**Core Dependencies**

* Microsoft Visual Studio 2022 -> [Here](https://visualstudio.microsoft.com/vs/)
* VS2022 Desktop Development With C++ 
* Windows 10 or 11 SDK _(Depending on your OS)_

**Optional**
* Autoit _(so you can modify the target binary)_ -> [Here](https://www.autoitscript.com/site/autoit/downloads/)
* StudPE _(if you want to inject the dll yourself)_ -> [Here](https://www.cgsoftlabs.ro/dl.html)
* Rohitab's API Monitor _(in case you want to monitor API Calls and research)_ -> [Here](http://www.rohitab.com/apimonitor)

### What are we Achieving?

We have a program, ```Victim.exe``` that is an **Autoit** script, compiled as a **x86**  binary that does the following:

1. **Connects** to google.com
2. **Sends** a simple HTTP Get Request
3. **Receives** the answer from Google's server

No big deal there, in fact we're not even using any sort of Library to send the HTTP Request, we're doing a raw ```TCPConnect()``` - a ```TCPSend()``` and a ```TCPRecv()```. We're just sending Packets over the network to a server, it mocks a Game executable, or a Software requesting an update.

A great thing about hooking Winsock's ```connect``` or ```WSAConnect``` is that you can change the **IPAddr:Port** a software wants to ```connect()``` to, it can be extremely useful when **reverse engineering network applications**. You can divert it to **localhost** or act as a **Proxy/MITM** without a lot of hassle. There are various approaches to achieving this, and the method described here is particularly effective.

### A Look at the Code

```cpp
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
typedef int (WSAAPI* WSARecvFunction)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, 
LPDWORD lpNumberOfBytesRecvd,
LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, 
LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

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

int WSAAPI DetouredWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, 
LPDWORD lpNumberOfBytesRecvd, 
LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, 
LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    printf("WSARecv - Buffer Count: %u\n", dwBufferCount);

    // Iterate through the lpBuffers array and print the size of each buffer
    for (DWORD i = 0; i < dwBufferCount; i++) {
        printf("Buffer %u Size: %u\n", i, lpBuffers[i].len);
    }

    int result = originalWSARecv(s, lpBuffers, dwBufferCount, 
	lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    Hexdump(lpBuffers->buf, 256); // You can adjust the size you want to dump here    
    return result;
}

extern "C" __declspec(dllexport) void Lain1337()
{
    // Exporting a dummy function
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
```

### Breaking Down the Code

Don't get scared, C++ has a lot of boilerplate code and sometimes it is not really intuitive, especially when dealing with WinAPI. Let's break down parts of the code so you can understand the code structure better.

```cpp
typedef int (WINAPI* ConnectFunction)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WINAPI* SendFunction)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* RecvFunction)(SOCKET s, char* buf, int len, int flags);
typedef int (WSAAPI* WSARecvFunction)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, 
LPDWORD lpNumberOfBytesRecvd,
LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, 
LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
```
In the context of Detours, these ```typedefs``` establish function pointer types that mirror the signatures of specific Windows API functions. 
Whenever you want to ```hook``` a function, you should read the documentation and properly understand each parameter, _pinvoke.net_ was a great source for that, even with code examples, but Microsoft discontinued the website, you will still be able to access WinAPI information on Microsoft's Official Documentation platform, and they do provide well documented information for almost all of their APIs. 
For example, you can learn more about ```WSARecv``` directly from microsoft [here](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv).

```cpp
ConnectFunction originalConnect = nullptr;
SendFunction originalSend = nullptr;
RecvFunction originalRecv = nullptr;
WSARecvFunction originalWSARecv = nullptr;
```

In this part of the code, we create four pointers: originalConnect, originalSend, originalRecv, and originalWSARecv. These pointers act like bookmarks for the original Windows functions we want to hook.

We set them to ```nullptr```, so that they don't point anywhere specific. It's a safety net to avoid pointing to the wrong place.
Later in the code, as we employ Detours to intercept these functions, we'll link these pointers to the genuine functions. 

```cpp
int WINAPI DetouredConnect(SOCKET s, const struct sockaddr* name, int namelen){
//[...]
}

int WINAPI DetouredSend(SOCKET s, const char* buf, int len, int flags){
//[...]
}

int WINAPI DetouredRecv(SOCKET s, char* buf, int len, int flags){
//[...]
}

int WSAAPI DetouredWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, 
LPDWORD lpNumberOfBytesRecvd, 
LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, 
LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine){
//[...]
}
```

These functions serve as the core of our hooking mechanism, where our custom code takes action. This is where we focus on implementing our desired changes, whether it's modifying the hostname, altering data, or any other necessary adjustments. After applying our custom logic, we proceed to call the original function, capture its return value, and typically return it (unless we intentionally want to modify the return value ourselves).


```cpp
extern "C" __declspec(dllexport) void Lain1337()
{
    // Exporting a dummy function
}
```

In this section of the code, we define a function called ```Lain1337``` and apply the ```extern``` and ```__declspec(dllexport)``` modifiers to it. These modifiers serve a specific purpose when we inject our ```DLL``` into a process using tools like StudPE.

When we inject a DLL into a process, we need a way for the process to locate and utilize the functionality provided by the DLL. To achieve this, we typically define an export function within our DLL. An export function acts as an entry point that other programs, including the process we inject the DLL into, can access and invoke.

In this case, ```Lain1337``` acts as a placeholder or dummy export function. It may not have any specific functionality associated with it, but it allows tools like StudPE to identify an entry point in our DLL. 

```cpp
if (AllocConsole()) {
    freopen("CONOUT$", "w", stdout);
    SetConsoleTitle(L"Injected Console");
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
    std::cout << "This is the injected console!" << std::endl;
}
```

Here, we're using ```AllocConsole()``` to create a new console window specifically for our DLL. This console will be used to print messages and debugging information while our DLL is running inside another process. This part is not needed, and you won't be doing that in a real Detours applications, especially since we have only one thread, and we'll be lagging the real API calls with our ```std::cout/printf``` - we're just doing it so it is an easy way to debug in real time.

```cpp
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
```

In this section, we are setting up the Detours framework to intercept and modify specific Windows API functions from the ```ws2_32.dll``` library. Here's what's happening:


1. Initialize the Winsock library using ```WSAStartup``` to enable networking functionality in our DLL.
2. Begin a Detours transaction using ```DetourTransactionBegin()``` to prepare for hooking functions.
3. Update the current thread using ```DetourUpdateThread(GetCurrentThread())``` to ensure that the Detours framework applies to the current thread.
4. Obtain the addresses of the original Windows API functions (connect, send, recv, and WSARecv) from the ```ws2_32.dll``` library using ```GetProcAddress```. These original functions will be called later after our custom code runs.
5. Attach our custom hook functions (DetouredConnect, DetouredSend, DetouredRecv, and DetouredWSARecv) to the original functions using ```DetourAttach```. This means that when any code calls the original functions, our custom functions will run before or after them, depending on the hooking logic.
6. Finally, we commit the Detours transaction using ```DetourTransactionCommit()```, which makes our hooks active.

**Part 1)** is not really necessary, unless you want to **debug** your DLL **remotely**. A trick that I have been using is that, whenever I want to debug or communicate with my Injected DLL, I send UDP Packets to a remote process, I do it on a separated thread, and due to the nature of UDP - it is a neat way to communicate and debug your injected dll.


### Our Victim Process

Our victim is a x86 (.exe) binary, that comes clean, without our Detours fiddling. 
Let's take a look on the AU3 source code.


```c
ConsoleWrite("[AU3] Victim.exe Launched!")
Opt("TCPTimeout", 1000)
TCPStartup()
$Connect = TCPConnect("142.250.218.14", 80)

If $Connect <> -1 Then
    TCPSend($Connect, "GET / HTTP/1.1" & @CRLF & _
                     "Host: www.google.com" & @CRLF & _
                     "Connection: close" & @CRLF & @CRLF)
    $TotalBytesReceived = 0
    Local $iTimeoutCounter = 0 ; Initialize the timeout counter
    For $i = 1 To 100 ; Just to make sure it doesn't run forever
        $Recv = TCPRecv($Connect, 256)
        If @error Then
            $iTimeoutCounter += 1
            If $iTimeoutCounter > 10 Then ExitLoop ; Exit after 10 seconds of no data
        Else
            ; Process the received data here
            $TotalBytesReceived += StringLen($Recv)
            If $TotalBytesReceived >= 256 Then ExitLoop ; Close the connection after receiving 256 bytes
        EndIf
        Sleep(100) ; Sleep for 100 milliseconds before the next iteration
    Next

    TCPCloseSocket($Connect)
EndIf

ConsoleWrite("[AU3] I Will close in 10 secs...")
TCPShutdown()
Sleep(10000)
Exit
```

### Watching API Calls

If we launch our Victim.exe with Rohitab's API Monitor, we'll be able to see the API Calls our target process is making.

![](/Img/Animation.gif)

### Adding our DLL to the Load Table
With StudPE you can add your DLL to the binary's import table. You can also inject the DLL in runtime, it will also work.

![](/Img/PETable.gif)


### Running our Victim after StudPE
Now that we've added our DLL to the import table of our binary, there should be a Console being allocated and the data it is sending/receiving should be printed.

![](/Img/DetConsole.gif)

### YAAAY - It works ٩(◕‿◕)۶!
Finally, we have a working Detours Project. Feel free to fiddle with the code! You can change the Host IP, you can edit the information being sent or received, you can inject this DLL at Runtime into other processes, and so on!

### License
This project is licensed under [GLWTPL](./LICENSE)







