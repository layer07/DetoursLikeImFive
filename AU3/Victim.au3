ConsoleWrite("[AU3] Victim.exe Launched!"&@CRLF)
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

ConsoleWrite(@CRLF&"[AU3] I Will close in 10 secs...")
TCPShutdown()
Sleep(10000)
Exit