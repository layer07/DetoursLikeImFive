Opt("TCPTimeout", 1000)
TCPStartup()
$Connect = TCPConnect("142.250.218.14", 80)

If $Connect <> -1 Then
    TCPSend($Connect, "GET / HTTP/1.1" & @CRLF & _
                     "Host: www.google.com" & @CRLF & _
                     "Connection: close" & @CRLF & @CRLF)

    $TotalBytesReceived = 0

    While 1
        $Recv = TCPRecv($Connect, 256)
        If @error Then ExitLoop
        ; Process the received data here
        $TotalBytesReceived += StringLen($Recv)
        If $TotalBytesReceived >= 256 Then ExitLoop ; Close the connection after receiving 1024 bytes
	WEnd
    TCPCloseSocket($Connect)
EndIf

ConsoleWrite("I Will close in 10 secs...")

TCPShutdown()

Sleep(10000)