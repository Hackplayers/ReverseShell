# ShellReverse
  
ReverseShell is a simple PowerShell script that we can use for 1/ easing the process of creating a reverse shell with different payloads depending on the interpreter that supports the server (python, bash, perl, java, php or ruby) and 2 / automating the update to Meterpreter.  

# Usage
  
Its syntax is very simple:  
  
  ./shell-reverse.ps1 -Lhost 10.10.10.1 -Lport 4444 -payload -web -metasploit  
  
- payload: python, python3, bash, perl, php, ruby, java  
- web: encode the payload for URL (encoder)  
- metasploit: start Metasploit and leave it waiting for session to update it to Meterpreter  

# Install in Debian or Kali

    git clone https://github.com/Hackplayers/ReverseShell
    cd shellreverse
    sudo apt-get update > /dev/null
    wget http://http.us.debian.org/debian/pool/main/libu/libunwind/libunwind8_1.1-4.1_amd64.deb 
    sudo dpkg -i libunwind8_1.1-4.1_amd64.deb
    wget http://archive.ubuntu.com/ubuntu/pool/main/i/icu/libicu55_55.1-7_amd64.deb
    sudo dpkg -i  libicu55_55.1-7_amd64.deb
    wget https://github.com/PowerShell/PowerShell/releases/download/v6.0.0-alpha.13/powershell_6.0.0-alpha.13-1ubuntu1.16.04.1_amd64.deb
    sudo dpkg -i powershell_6.0.0-alpha.13-1ubuntu1.16.04.1_amd64.deb
    powershell
    ./shell-reverse.ps1 -LHOST 192.168.1.20 -LPORT 4444 -Lenguaje

# Languaje
&nbsp;&nbsp;&nbsp;**Perl**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Python**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Python3**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Ruby**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**PHP**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Java**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Bash**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**Netcat**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**PowershellTCP**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**PowerrshellUDP**&nbsp;&nbsp;  
&nbsp;&nbsp;&nbsp;**PowershellICMP**&nbsp;&nbsp;  
  

# Video Example
![](https://github.com/cybervaca/ShellReverse/blob/master/example.gif)

# AutoUpdate to Meterpreter
