#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - recon
################### #### ## #  #    #
#
# >> this file contains the "recon" sub menu and all it's functions

nmap_ports=""
nmap_speed=""
nmap_script=""
nmap_osver=""
nmap_output=""
nmap_verbose=""

ferox_output=""
ferox_recurse=""
ferox_statcode=""
ferox_useragent=""
ferox_verbose=""

nikto_output=""
nikto_useragent=""
nikto_verbose=""
nikto_ssl=""

cmseek_output=""
cmseek_useragent=""
cmseek_verbose=""
cmseek_lightscan=""
cmseek_redirect=""

wpscan_enum=""
wpscan_output=""
wpscan_useragent=""
wpscan_verbose=""
wpscan_ssl=""
wpscan_threads=""
wpscan_passlist=""
wpscan_user=""

sqlmap_detect=""
sqlmap_enum=""
sqlmap_shell=""
sqlmap_useragent=""
sqlmap_ssl=""
sqlmap_verbose=""
sqlmap_batch=""
sqlmap_threads=""

menu_recon()
{
    menu="$(pfx -n "NMAP") NMAP scan\n<small>port scan the target's IP</small>$lb$(pfx -n "HTTP") HTTP-related scans\n<small>from directory/file scans to CMS scans!</small>$lb$(pfx -n "SMB") SMB-related scans\n<small>scans SMB services for shares, passwords, etc.</small>$lb$lbrk$lb$(pfx -n "BACK") go back..."
	msg="pwnMENU > <b>recon</b>\n<small>the below tools will help you do your initial scanning on the target, to hopefully get you that initial foothold.</small>"
	result=$(echo -e "$menu" | rf "RECON" "$msg" 5)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"NMAP")
			recon_nmap
			;;
		"HTTP")
			recon_http
			;;
		"SMB")
			recon_smb
			;;
		"BACK")
			main
			;;
	esac
}

recon_nmap()
{
    app="nmap"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$target_ip" == "" ]; then
        rf_msg "$(pfx -n "ERROR") you need to set a target IP address (main menu)..."
        menu_recon
        break
    else
        menu="$(pfx -n "SCANTYPE") $nmap_scan_type\n<small>set the type of scan to perform</small>$lb$(pfx -n "HOSTDISC") $nmap_hostdisc\n<small>enable or disable host discovery (disable for most windows machines)</small>$lb$(pfx -n "PORTS") $nmap_ports\n<small>(optional) set amount of top X ports, scan a range, single or multiple ports in a list</small>$lb$(pfx -n "SPEED") $nmap_speed\n<small>(optional) configure how quick NMAP will scan (can cause inaccuracy)</small>$lb$(pfx -n "SCRIPT") $nmap_script\n<small>(optional) run NMAP script(s) on the target after scan</small>$lb$(pfx -n "OSVER") $nmap_osver\n<small>(optional) version / OS scanning</small>$lb$(pfx -n "OUTPUT") $nmap_output\n<small>(optional) output of NMAP scan to file in various formats</small>$lb$(pfx "VERBOSE") $nmap_verbose\n(optional) change verbosity of output$lb$lbrk$lb$(pfx -n "GEN") generate NMAP scan command$lb$(pfx -n "BACK") go back..."
        msg="pwnMENU > RECON > <b>NMAP</b>\n<small>build a NMAP scan command tailored to your (basic) needs!</small>"
        result=$(echo -e "$menu" | rf "NMAP" "$msg" 11)
        result=$(echo $result | awk '{print $1}')
        case $result in
            "SCANTYPE")
                msg="pwnMENU > RECON > NMAP > <b>SCANTYPE</b>\n<small>select the type of scan to perform</small>"
                menu="$(pfx "-sS") syn scan\n<small>(requires sudo)</small>$lb$(pfx "-sT") tcp connect scan$lb$(pfx "-sN") tcp null scan\n<small>(requires sudo)</small>$lb$(pfx "-sF") tcp fin scan\n<small>(requires sudo)</small>$lb$(pfx "-sX") tcp xmas scan\n<small>(requires sudo)</small>"
                result=$(echo -e "$menu" | rf "SCANTYPE" "$msg" 4)
                nmap_scan_type="$(echo $result | awk '{print $1}')"
                recon_nmap
                ;;
            "HOSTDISC")
                msg="pwnMENU > RECON > NMAP > <b>HOSTDISC</b>\n<small>enable (default) / disable host discovery (necessary if host blocks ping probes)</small>"
                menu="$(pfx "ON") leave host discovery enabled$lb$(pfx "OFF") disable host discovery"
                result=$(echo -e "$menu" | rf "HOSTDISC" "$msg" 2)
                nmap_hostdisc="$(echo $result | awk '{print $1}')"
                recon_nmap
                ;;
            "PORTS")
                msg="pwnMENU > RECON > NMAP > <b>PORTS</b>\n<small>(optional) select amount of top-ports to scan, a custom range / list or scan all ports</small>"
                menu="$(pfx "N/A") scan default (top 1000) ports$lb$(pfx "--top-ports") scan X ports from the top ports list$lb$(pfx "-p-") scan ALL ports$lb$(pfx "-p") custom port range"
                result=$(echo -e "$menu" | rf "PORTS" "$msg" 4)
                result=$(echo $result | awk '{print $1}')
                case $result in
                    "N/A")
                        nmap_ports=""
                        recon_nmap
                        ;;
                    "--top-ports")
                        msg="pwnMENU > RECON > NMAP > PORTS > <b>--top-ports</b>\n<small>enter the amount of top ports to scan</small>"
                        amount=$(echo '' | rf "AMOUNT" "$msg" 0)
                        nmap_ports="--top-ports $amount"
                        recon_nmap
                        ;;
                    "-p-")
                        nmap_ports="-p-"
                        recon_nmap
                        ;;
                    "-p")
                        msg="pwnMENU > RECON > NMAP > PORTS > <b>-p</b>\n<small>enter a single port, range ([1]-[65535]) or a comma-seperated list of ports to scan</small>"
                        range=$(echo '' | rf "RANGE" "$msg" 0)
                        nmap_ports="-p$range"
                        recon_nmap
                        ;;
                esac
                ;;
            "SPEED")
                msg="pwnMENU > RECON > NMAP > <b>SPEED</b>\n<small>(optional) limit or increase the speed of the scan (faster scans can provide inaccurate results)</small>"
                menu="$(pfx "N/A") scan default speed (-T3)$lb$(pfx "-T") scan custom speed (1-5)"
                result=$(echo -e "$menu" | rf "SPEED" "$msg" 2)
                result=$(echo $result | awk '{print $1}')
                case $result in
                    "N/A")
                        nmap_speed=""
                        recon_nmap
                        ;;
                    "-T")
                        msg="pwnMENU > RECON > NMAP > PORTS > <b>-T</b>\n<small>enter a number between 1 (slowest) to 5 (fastest) to set scan speed</small>"
                        amount=$(echo '' | rf "AMOUNT" "$msg" 0)
                        if [ $amount -lt 5 ] || [ $amount -gt 1 ]; then
                            nmap_speed="-T$amount"
                        else
                            rf_msg "$(pfx -n "ERROR") you must set a number between 1 and 5..."
                            nmap_speed=""
                        fi
                        recon_nmap
                        ;;
                esac
                ;;
            "SCRIPT")
                menu="$(pfx "N/A") don't execute any scripts\n$(pfx "-sC") execute default scripts\n$lbrk\n$(find /usr/share/nmap/scripts/ -name '*.nse' | sed 's|/usr/share/nmap/scripts/||')"
                result=$(echo -e "$menu" | rf "SCRIPT")
                if [ "$(echo $result | awk '{print $1}')" == "N/A" ] || [ "$result" == "$lbrk" ]; then
                    nmap_script=""
                elif [ "$(echo $result | awk '{print $1}')" == "-sC" ]; then
                    nmap_script="-sC"
                else
                    nmap_script="--script $result"
                fi
                recon_nmap
                ;;
            "OSVER")
                msg="pwnMENU > RECON > NMAP > <b>OSVER</b>\n<small>(optional) try to detect OS version, versions of services found open, or both + more (traceroute, script scans)</small>"
                menu="$(pfx "N/A") no OS / version detection$lb$(pfx "-sV") show service versions (banners)$lb$(pfx "-O") try to detect target OS$lb$(pfx "-A") OS / version / traceroute / script scan detection"
                result=$(echo -e "$menu" | rf "OSVER" "$msg" 4)
                result=$(echo $result | awk '{print $1}')
                if [ "$result" == "N/A" ]; then
                    nmap_osver=""
                else
                    nmap_osver="$result"
                fi
                recon_nmap
                ;;
            "OUTPUT")
                msg="pwnMENU > RECON > NMAP > <b>OUTPUT</b>\n<small>(optional) output NMAP scan details in various formats</small>"
                menu="$(pfx "N/A") no output$lb$(pfx "-oN") normal (text) output$lb$(pfx "-oX") XML output$lb$(pfx "-oG") greppable output$lb$(pfx "-oA") output all formats"
                result=$(echo -e "$menu" | rf "OUTPUT" "$msg" 5)
                result=$(echo $result | awk '{print $1}')
                if [ "$result" == "N/A" ]; then
                    nmap_output=""
                else
                    msg="pwnMENU > RECON > NMAP > OUTPUT > <b>FILENAME</b>\n<small>please provide a (base) filename for the output</small>"
                    filename=$(echo '' | rf "FILENAME" "$msg" 0)
                    nmap_output="$result $filename"
                fi
                recon_nmap
                ;;
            "VERBOSE")
                msg="pwnMENU > RECON > NMAP > <b>VERBOSE</b>\n<small>(optional) set the verbosity of NMAP output</small>"
                menu="$(pfx "N/A") no verbosity$lb$(pfx "-v") standard verbosity$lb$(pfx "-vv") extra verbose"
                result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
                result=$(echo $result | awk '{print $1}')
                case $result in
                    "N/A")
                        nmap_verbose=""
                        recon_nmap
                        ;;
                    "-v")
                        nmap_verbose="-v"
                        recon_nmap
                        ;;
                    "-vv")
                        nmap_verbose="-vv"
                        recon_nmap
                        ;;
                esac
                ;;
            "GEN")
                if [ "$nmap_scan_type" != "-sT" ]; then
                    payload="sudo nmap $nmap_scan_type "
                else
                    payload="nmap $nmap_scan_type "
                fi
                if [ "$nmap_hostdisc" == "OFF" ]; then      payload="$payload -Pn "; fi
                if [ "$nmap_ports" != "" ]; then            payload="$payload $nmap_ports "; fi
                if [ "$nmap_speed" != "" ]; then            payload="$payload $nmap_speed "; fi
                if [ "$nmap_verbose" != "" ]; then          payload="$payload $nmap_verbose "; fi
                if [ "$nmap_osver" != "" ]; then            payload="$payload $nmap_osver "; fi
                if [ "$nmap_script" != "" ]; then           payload="$payload $nmap_script "; fi
                if [ "$nmap_output" != "" ]; then           payload="$payload $nmap_output "; fi
                payload="$payload $target_ip"
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") $1 NMAP scan command copied to the clipboard."
                exit 0
                ;;
            "BACK")
                menu_recon
                ;;
        esac
    fi
}

recon_http()
{
    if [ "$target_ip" == "" ]; then
        rf_msg "$(pfx -n "ERROR") you need to set a target IP address (main menu)..."
        menu_recon
        break
    else
        menu="$(pfx -n "FEROX") FeroxBuster directory / file scan\n<small>crawls website files and directories using wordlists</small>$lb$(pfx -n "NIKTO") Nikto scan\n<small>checks target webserver for known misconfigurations that can lead to exploitation</small>$lb$(pfx -n "CMSEEK") CMSeeK scan\n<small>checks website address for known CMS and tries to gather information about the CMS setup</small>$lb$(pfx -n "WPSCAN") wp-scan - wordpress scanner\n<small>scans wordpress sites for known misconfigurations and credentials</small>$lb$(pfx -n "SQLMAP") SQLmap\n<small>test url for SQL injection methods</small>$lb$lbrk$lb$(pfx -n "BACK") go back..."
        msg="pwnMENU > RECON > <b>HTTP</b>\n<small>website-related scanners to help you enumerate websites</small>"
        result=$(echo -e "$menu" | rf "FEROX" "$msg" 7)
        result=$(echo $result | awk '{print $1}')
        case $result in
            "FEROX")
                recon_ferox
                ;;
            "NIKTO")
                recon_nikto
                ;;
            "CMSEEK")
                recon_cmseek
                ;;
            "WPSCAN")
                recon_wpscan
                ;;
            "SQLMAP")
                recon_sqlmap
                ;;
            "BACK")
                menu_recon
                ;;
        esac
    fi
}

recon_ferox()
{
    app="feroxbuster"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$ferox_url" == "" ]; then
        ferox_url="http://$target_ip/"
    fi
    if [ "$ferox_wordlist" == "" ]; then
        ferox_wordlist="$def_http_wordlist"
    fi
    msg="pwnMENU > RECON > HTTP > <b>FEROX</b>\n<small>FeroxBuster crawls websites searching for files and directories based off supplied wordlist</small>"
    menu="$(pfx "URL") $ferox_url\nURL to scan with FeroxBuster$lb$(pfx "WORDLIST") $ferox_wordlist\nwordlist to use for scan$lb$(pfx "RECURSE") $ferox_recurse\n(optional) directory recursion settings (default = -d 4)$lb$(pfx "OUTPUT") $ferox_output\n(optional) output results to file (default = none)$lb$(pfx "STATCODE") $ferox_statcode\n(optional) HTTP status codes to allow as positive result$lb$(pfx "USERAGNT") $ferox_useragent\n(optional) user-agent to send with request$lb$(pfx "VERBOSE") $ferox_verbose\n(optional) change verbosity of output$lb$lbrk$lb$(pfx "GEN") generate FeroxBuster command$lb$(pfx "BACK") go back..."
    result=$(echo -e "$menu" | rf "SCANTYPE" "$msg" 10)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "URL")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>URL</b>\n<small>enter or select the URL to be scanned with FeroxBuster</small>"
            urls="$(pfx "TARGET") http://$target_ip/"
            result=$(echo -e "$urls" | rf "FEROX" "$msg" 1)
            if [ "$(echo $result | awk '{print $2}')" == "❯❯" ]; then
                ferox_url=$(echo $result | awk '{print $3}')
            else
                ferox_url=$(echo $result | awk '{print $1}')
            fi
            recon_ferox
            ;;
        "WORDLIST")
            ferox_wordlist
            ;;
        "RECURSE")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>RECURSE</b>\n<small>(optional) directory recursion settings (default = -d 4)</small>"
            menu="$(pfx "N/A") default recursion (default = -d 4)$lb$(pfx "--no-recursion") no recursion$lb$(pfx "-d") set maximum recursion depth (0 = infinite)"
            result=$(echo -e "$menu" | rf "RECURSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    ferox_recurse=""
                    recon_ferox
                    ;;
                "--no-recursion")
                    ferox_recurse="-n"
                    recon_ferox
                    ;;
                "-d")
                    msg="pwnMENU > RECON > HTTP > FEROX > RECURSE > <b>-d</b>\n<small>enter the depth of recursion (0 = infinite)</small>"
                    amount=$(echo '' | rf "DEPTH" "$msg" 0)
                    ferox_recurse="-d $amount"
                    recon_ferox
                    ;;
            esac
            ;;
        "OUTPUT")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>OUTPUT</b>\n<small>(optional) output FeroxBuster scan details to a file (default = none)</small>"
            menu="$(pfx "N/A") do not output to a file$lb$(pfx "-o") output to a file"
            result=$(echo -e "$menu" | rf "OUTPUT" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    ferox_output=""
                    recon_ferox
                    ;;
                "-o")
                    msg="pwnMENU > RECON > HTTP > FEROX > OUTPUT > <b>-o</b>\n<small>enter the filename for output</small>"
                    filename=$(echo '' | rf "OUTFILE" "$msg" 0)
                    ferox_output="-o $filename"
                    recon_ferox
                    ;;
            esac
            ;;
        "STATCODE")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>STATCODE</b>\n<small>(optional) HTTP status codes to allow as positive result (default = 200 204 301 302 307 308 401 403 405)</small>"
            menu="$(pfx "N/A") allow default status codes$lb$(pfx "-s") allow custom status code list"
            result=$(echo -e "$menu" | rf "STATCODE" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    ferox_statcode=""
                    recon_ferox
                    ;;
                "-s")
                    msg="pwnMENU > RECON > HTTP > FEROX > OUTPUT > <b>-s</b>\n<small>enter status codes (seperated by space) that you wish to allow</small>"
                    codes=$(echo '' | rf "CODES" "$msg" 0)
                    ferox_statcode="-s '$codes'"
                    recon_ferox
                    ;;
            esac
            ;;
        "USERAGNT")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>USERAGNT</b>\n<small>(optional) set or randomize the User-Agent property sent with each request (default = feroxbuster/VERSION)</small>"
            menu="$(pfx "N/A") use default user-agent$lb$(pfx "-A") use random user-agent$lb$(pfx "-a") set custom user-agent"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    ferox_useragent=""
                    recon_ferox
                    ;;
                "-A")
                    ferox_useragent="-A"
                    recon_ferox
                    ;;
                "-s")
                    msg="pwnMENU > RECON > HTTP > FEROX > USERAGNT > <b>-a</b>\n<small>enter custom user-agent to use</small>"
                    useragent=$(echo '' | rf "USERAGNT" "$msg" 0)
                    ferox_useragent="-s $codes"
                    recon_ferox
                    ;;
            esac
            ;;
        "VERBOSE")
            msg="pwnMENU > RECON > HTTP > FEROX > <b>VERBOSE</b>\n<small>(optional) set the verbosity of FeroxBuster output</small>"
            menu="$(pfx "N/A") no verbosity$lb$(pfx "-v") standard verbosity$lb$(pfx "-vv") extra verbose"
            result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    ferox_verbose=""
                    recon_ferox
                    ;;
                "-v")
                    ferox_verbose="-v"
                    recon_ferox
                    ;;
                "-vv")
                    ferox_verbose="-vv"
                    recon_ferox
                    ;;
            esac
            ;;
        "GEN")
            if [ "$ferox_url" == "" ] || [ "$ferox_wordlist" == "" ]; then
                rf_msg "$(pfx "ERROR") you have not set the necessary settings - please ensure you set at least a URL and wordlist"
                recon_ferox
            else
                payload="feroxbuster -u $ferox_url -w $ferox_wordlist"
                if [ "$ferox_recurse" != "" ]; then     payload="$payload $ferox_recurse"; fi
                if [ "$ferox_verbose" != "" ]; then     payload="$payload $ferox_verbose"; fi
                if [ "$ferox_useragent" != "" ]; then   payload="$payload $ferox_useragent"; fi
                if [ "$ferox_statcode" != "" ]; then    payload="$payload $ferox_statcode"; fi
                if [ "$ferox_output" != "" ]; then      payload="$payload $ferox_output"; fi
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") $1 FeroxBuster command copied to the clipboard."
                exit 0
            fi
            ;;
        "BACK")
            menu_recon
            ;;
    esac
}


ferox_wordlist()
{
    if [ "$curr_dir" == "" ]; then
        curr_dir="$wordlists_dir"
    fi
    folders=$(echo -e "$(pfx -n "BACK") $curr_dir\n$lbrk"; ls -1 $curr_dir)
	result=$(echo -ne "$folders" | rf "WORDLIST")
    result=$(echo $result | awk '{print $1}')
	case $result in
        "BACK")
            curr_dir=$(dirname $curr_dir)
            ferox_wordlist
            ;;
        "$lbrk")
            ferox_wordlist
            ;;
        *)
            if [ "$result" != "" ]; then
                if [ "$curr_dir" == "/" ]; then
                    curr_dir="/$result"
                else
                    curr_dir="$curr_dir/$result"
                fi
                if [ -d "$curr_dir" ]; then
                    ferox_wordlist
                else
                    ferox_wordlist="$curr_dir"
                    rf_msg "$(pfx -n "INFO") FeroxBuster wordlist set to '$ferox_wordlist'."
                    curr_dir=""
                    recon_ferox
                fi
            else
                recon_ferox
            fi
            ;;
    esac
}

recon_nikto()
{
    app="nikto"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$nikto_url" == "" ]; then
        nikto_url="http://$target_ip/"
    fi
    msg="pwnMENU > RECON > HTTP > <b>NIKTO</b>\n<small>Nikto checks target webserver for known misconfigurations that can lead to exploitation</small>"
    menu="$(pfx "URL") $nikto_url\nURL to scan with Nikto$lb$(pfx "OUTPUT") $nikto_output\n(optional) output results to file (default = none)$lb$(pfx "USERAGNT") $nikto_useragent\n(optional) user-agent to send with request$lb$(pfx "SSL") $nikto_ssl\n(optional) disable or force ssl$lb$(pfx "VERBOSE") $nikto_verbose\n(optional) change verbosity of output$lb$lbrk$lb$(pfx "GEN") generate Nikto command$lb$(pfx "BACK") go back..."
    result=$(echo -e "$menu" | rf "NIKTO" "$msg" 8)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "URL")
            msg="pwnMENU > RECON > HTTP > NIKTO > <b>URL</b>\n<small>enter or select the URL to be scanned with Nikto</small>"
            urls="$(pfx "TARGET") http://$target_ip/"
            result=$(echo -e "$urls" | rf "URL" "$msg" 1)
            if [ "$(echo $result | awk '{print $2}')" == "❯❯" ]; then
                nikto_url=$(echo $result | awk '{print $3}')
            else
                nikto_url=$(echo $result | awk '{print $1}')
            fi
            recon_nikto
            ;;
        "OUTPUT")
            msg="pwnMENU > RECON > HTTP > NIKTO > <b>OUTPUT</b>\n<small>(optional) output Nikto scan details to a file</small>"
            menu="$(pfx "N/A") do not output to a file$lb$(pfx "-output") output to a file"
            result=$(echo -e "$menu" | rf "OUTPUT" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    nikto_output=""
                    recon_nikto
                    ;;
                "-output")
                    msg="pwnMENU > RECON > HTTP > NIKTO > OUTPUT > <b>-output</b>\n<small>enter the filename for output</small>"
                    filename=$(echo '' | rf "OUTFILE" "$msg" 0)
                    formats="$(pfx "CSV") comma-separated-value$lb$(pfx "HTM") HTML format$lb$(pfx "NBE") Nessus NBE format$lb$(pfx "SQL") Generic SQL$lb$(pfx "TXT") plain text$lb$(pfx "XML") XML format"
                    msg="pwnMENU > RECON > HTTP > NIKTO > OUTPUT > <b>-Format</b>\n<small>select the format for output</small>"
                    format=$(echo -e "$formats" | rf "FORMAT" "$msg" 6)
                    format=$(echo $format | awk '{print $1}')
                    nikto_output="-output \$PWD/$filename -Format $format"
                    recon_nikto
                    ;;
            esac
            ;;
        "USERAGNT")
            msg="pwnMENU > RECON > HTTP > NIKTO > <b>USERAGNT</b>\n<small>(optional) set the User-Agent property sent with each request</small>"
            menu="$(pfx "N/A") use default user-agent$lb$(pfx "-useragent") set custom user-agent"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    nikto_useragent=""
                    recon_nikto
                    ;;
                "-useragent")
                    msg="pwnMENU > RECON > HTTP > NIKTO > USERAGNT > <b>-useragent</b>\n<small>enter custom user-agent to use</small>"
                    useragent=$(echo '' | rf "USERAGNT" "$msg" 0)
                    nikto_useragent="-useragent '$useragent'"
                    recon_nikto
                    ;;
            esac
            ;;
        "SSL")
            msg="pwnMENU > RECON > HTTP > NIKTO > <b>SSL</b>\n<small>(optional) force or disable using SSL</small>"
            menu="$(pfx "N/A") leave ssl default$lb$(pfx "-nossl") disable usage of ssl$lb$(pfx "-ssl") force usage of ssl"
            result=$(echo -e "$menu" | rf "SSL" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    nikto_ssl=""
                    recon_nikto
                    ;;
                "-nossl")
                    nikto_ssl="-nossl"
                    recon_nikto
                    ;;
                "-ssl")
                    nikto_ssl="-ssl"
                    recon_nikto
                    ;;
            esac
            ;;
        "VERBOSE")
            msg="pwnMENU > RECON > HTTP > NIKTO > <b>VERBOSE</b>\n<small>(optional) set the verbosity of Nikto output</small>"
            menu="$(pfx "N/A") no verbosity$lb$(pfx "-Display V") enable verbosity"
            result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    nikto_verbose=""
                    recon_nikto
                    ;;
                "-Display V")
                    nikto_verbose="-Display V"
                    recon_nikto
                    ;;
            esac
            ;;
        "GEN")
            if [ "$nikto_url" == "" ]; then
                rf_msg "$(pfx "ERROR") you have not set the necessary settings - you must set at least a URL"
                recon_nikto
            else
                payload="nikto -h $nikto_url"
                if [ "$nikto_ssl" != "" ]; then         payload="$payload $nikto_ssl"; fi
                if [ "$nikto_verbose" != "" ]; then     payload="$payload $nikto_verbose"; fi
                if [ "$nikto_useragent" != "" ]; then   payload="$payload $nikto_useragent"; fi
                if [ "$nikto_output" != "" ]; then      payload="$payload $nikto_output"; fi
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") $1 Nikto command copied to the clipboard."
                exit 0
            fi
            ;;
        "BACK")
            menu_recon
            ;;
    esac
}

recon_cmseek()
{
    app="cmseek"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$cmseek_url" == "" ]; then
        cmseek_url="http://$target_ip/"
    fi
    msg="pwnMENU > RECON > HTTP > <b>CMSEEK</b>\n<small>CMSeeK checks target webserver for known misconfigurations that can lead to exploitation</small>"
    menu="$(pfx "URL") $cmseek_url\nURL to scan with CMSeeK$lb$(pfx "USERAGNT") $cmseek_useragent\n(optional) user-agent to send with request$lb$(pfx "LITESCAN") $cmseek_lightscan\n(optional) whether to use light-scan mode or not$lb$(pfx "REDIRECT") $cmseek_redirect\n(optional) follow or ignore redirects$lb$(pfx "VERBOSE") $cmseek_verbose\n(optional) change verbosity of output$lb$lbrk$lb$(pfx "GEN") generate CMSeeK command$lb$(pfx "BACK") go back..."
    result=$(echo -e "$menu" | rf "CMSEEK" "$msg" 8)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "URL")
            msg="pwnMENU > RECON > HTTP > CMSEEK > <b>URL</b>\n<small>enter or select the URL to be scanned with CMSeeK</small>"
            urls="$(pfx "TARGET") http://$target_ip/"
            result=$(echo -e "$urls" | rf "URL" "$msg" 1)
            if [ "$(echo $result | awk '{print $2}')" == "❯❯" ]; then
                cmseek_url=$(echo $result | awk '{print $3}')
            else
                cmseek_url=$(echo $result | awk '{print $1}')
            fi
            recon_cmseek
            ;;
        "LITESCAN")
            msg="pwnMENU > RECON > HTTP > CMSEEK > <b>LITESCAN</b>\n<small>(optional) enable or disable light-scan mode (skips deep scanning)</small>"
            menu="$(pfx "N/A") use default$lb$(pfx "--light-scan") enable light-scan mode"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    cmseek_lightscan=""
                    recon_cmseek
                    ;;
                "--light-scan")
                    cmseek_lightscan="--light-scan"
                    recon_cmseek
                    ;;
            esac
            ;;
        "USERAGNT")
            msg="pwnMENU > RECON > HTTP > CMSEEK > <b>USERAGNT</b>\n<small>(optional) set the User-Agent property sent with each request</small>"
            menu="$(pfx "N/A") use default user-agent$lb$(pfx "--random-agent") set random user-agent$lb$(pfx "--googlebot") use googlebot user-agent$lb$(pfx "--user-agent") set custom user-agent"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 5)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    cmseek_useragent=""
                    recon_cmseek
                    ;;
                "--random-agent")
                    cmseek_useragent="--random-agent"
                    recon_cmseek
                    ;;
                "--googlebot")
                    cmseek_useragent="--googlebot"
                    recon_cmseek
                    ;;
                "--user-agent")
                    msg="pwnMENU > RECON > HTTP > CMSEEK > USERAGNT > <b>--user-agent</b>\n<small>enter custom user-agent to use</small>"
                    useragent=$(echo '' | rf "USERAGNT" "$msg" 0)
                    cmseek_useragent="--user-agent '$useragent'"
                    recon_cmseek
                    ;;
            esac
            ;;
        "REDIRECT")
            msg="pwnMENU > RECON > HTTP > CMSEEK > <b>REDIRECT</b>\n<small>(optional) choose whether to follow or ignore redirects</small>"
            menu="$(pfx "N/A") leave default$lb$(pfx "--follow-redirect") follow redirects$lb$(pfx "--no-redirect") ignore redirects"
            result=$(echo -e "$menu" | rf "REDIRECT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    cmseek_redirect=""
                    recon_cmseek
                    ;;
                "--follow-redirect")
                    cmseek_redirect="--follow-redirect"
                    recon_cmseek
                    ;;
                "--no-redirect")
                    cmseek_redirect="--no-redirect"
                    recon_cmseek
                    ;;
            esac
            ;;
        "VERBOSE")
            msg="pwnMENU > RECON > HTTP > CMSEEK > <b>VERBOSE</b>\n<small>(optional) set the verbosity of CMSeeK output</small>"
            menu="$(pfx "N/A") no verbosity$lb$(pfx "-v") enable verbosity"
            result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    cmseek_verbose=""
                    recon_cmseek
                    ;;
                "-v")
                    cmseek_verbose="-v"
                    recon_cmseek
                    ;;
            esac
            ;;
        "GEN")
            if [ "$cmseek_url" == "" ]; then
                rf_msg "$(pfx "ERROR") you have not set the necessary settings - you must set at least a URL"
                recon_cmseek
            else
                payload="cmseek -u $cmseek_url"
                if [ "$cmseek_lightscan" != "" ]; then  payload="$payload $cmseek_lightscan"; fi
                if [ "$cmseek_verbose" != "" ]; then    payload="$payload $cmseek_verbose"; fi
                if [ "$cmseek_useragent" != "" ]; then  payload="$payload $cmseek_useragent"; fi
                if [ "$cmseek_redirect" != "" ]; then   payload="$payload $cmseek_redirect"; fi
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") $1 CMSeeK command copied to the clipboard."
                exit 0
            fi
            ;;
        "BACK")
            menu_recon
            ;;
    esac
}

recon_wpscan()
{
    app="wpscan"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$wpscan_url" == "" ]; then
        wpscan_url="http://$target_ip/"
    fi
    msg="pwnMENU > RECON > HTTP > <b>WPSCAN</b>\n<small>WP-Scan checks target webserver for known misconfigurations that can lead to exploitation</small>"
    menu="$(pfx "URL") $wpscan_url\nURL to scan with WP-Scan$lb$(pfx "OUTPUT") $wpscan_output\n(optional) output results to file (default = none)$lb$(pfx "USER") $wpscan_user\n(optional) single, list or text file for usernames to test$lb$(pfx "PASSLIST") $wpscan_passlist\n(optional) select a password list to use against found users$lb$(pfx "ENUM") $wpscan_enum\n(optional) tweak enumeration settings$lb$(pfx "USERAGNT") $wpscan_useragent\n(optional) user-agent to send with request$lb$(pfx "THREADS") $wpscan_threads\n(optional) set maximum threads to use$lb$(pfx "SSL") $wpscan_ssl\n(optional) disable certificate checking when using SSL$lb$(pfx "VERBOSE") $wpscan_verbose\n(optional) change verbosity of output$lb$lbrk$lb$(pfx "GEN") generate WP-Scan command$lb$(pfx "BACK") go back..."
    result=$(echo -e "$menu" | rf "WPSCAN" "$msg" 12)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "URL")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>URL</b>\n<small>enter or select the URL to be scanned with WP-Scan</small>"
            urls="$(pfx "TARGET") http://$target_ip/"
            result=$(echo -e "$urls" | rf "URL" "$msg" 1)
            if [ "$(echo $result | awk '{print $2}')" == "❯❯" ]; then
                wpscan_url=$(echo $result | awk '{print $3}')
            else
                wpscan_url=$(echo $result | awk '{print $1}')
            fi
            recon_wpscan
            ;;
        "OUTPUT")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>OUTPUT</b>\n<small>(optional) output WP-Scan scan details to a file</small>"
            menu="$(pfx "N/A") do not output to a file$lb$(pfx "-o") output to a file"
            result=$(echo -e "$menu" | rf "OUTPUT" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_output=""
                    recon_wpscan
                    ;;
                "-o")
                    msg="pwnMENU > RECON > HTTP > WPSCAN > OUTPUT > <b>-output</b>\n<small>enter the filename for output</small>"
                    filename=$(echo '' | rf "OUTFILE" "$msg" 0)
                    wpscan_output="-o \$PWD/$filename"
                    recon_wpscan
                    ;;
            esac
            ;;
        "USER")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>USER</b>\n<small>(optional) set a single, comma-seperated list or pick a list of usernames to enumerate</small>"
            menu="$(pfx "N/A") don't set username(s) or userlist$lb$(pfx "USERS") set either single or comma-serpated user(s)$lb$(pfx "LIST") select a username list"
            result=$(echo -e "$menu" | rf "USER" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_user=""
                    recon_wpscan
                    ;;
                "USERS")
                    msg="pwnMENU > RECON > HTTP > WPSCAN > USERAGNT > <b>-useragent</b>\n<small>enter either single user or comma-seperated list of users</small>"
                    users=$(echo '' | rf "USERS" "$msg" 0)
                    wpscan_user="-U $users"
                    recon_wpscan
                    ;;
                "LIST")
                    wpscan_userlist
                    ;;
            esac
            ;;
        "PASSLIST")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>PASSLIST</b>\n<small>(optional) set a password list to use for enumerating user credentials</small>"
            menu="$(pfx "N/A") don't set a password list$lb$(pfx "-P") set a password list"
            result=$(echo -e "$menu" | rf "USER" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_passlist=""
                    recon_wpscan
                    ;;
                "-P")
                    wpscan_passlist
                    ;;
            esac
            ;;
        "ENUM")
            wpscan_enum
            ;;
        "USERAGNT")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>USERAGNT</b>\n<small>(optional) set the User-Agent property sent with each request</small>"
            menu="$(pfx "N/A") use default user-agent$lb$(pfx "--rua") set random user-agent$lb$(pfx "--ua") set custom user-agent"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_useragent=""
                    recon_wpscan
                    ;;
                "--rua")
                    wpscan_useragent="--rua"
                    recon_wpscan
                    ;;
                "--ua")
                    msg="pwnMENU > RECON > HTTP > WPSCAN > USERAGNT > <b>-useragent</b>\n<small>enter custom user-agent to use</small>"
                    useragent=$(echo '' | rf "USERAGNT" "$msg" 0)
                    wpscan_useragent="--ua '$useragent'"
                    recon_wpscan
                    ;;
            esac
            ;;
        "THREADS")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>THREADS</b>\n<small>(optional) set the maximum threads used (default = 5)</small>"
            menu="$(pfx "N/A") use default max-threads$lb$(pfx "-t") set amount of max-threads"
            result=$(echo -e "$menu" | rf "THREADS" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_threads=""
                    recon_wpscan
                    ;;
                "-t")
                    msg="pwnMENU > RECON > HTTP > WPSCAN > USERAGNT > <b>-t</b>\n<small>enter maximum threads to use (default = 5)</small>"
                    threads=$(echo '' | rf "THREADS" "$msg" 0)
                    wpscan_threads="-t $threads"
                    recon_wpscan
                    ;;
            esac
            ;;
        "SSL")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>SSL</b>\n<small>(optional) disable certificate checking when using SSL</small>"
            menu="$(pfx "N/A") check ssl/tls certificates$lb$(pfx "--disable-tls-checks") disable ssl/tls certificate checks"
            result=$(echo -e "$menu" | rf "SSL" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_ssl=""
                    recon_wpscan
                    ;;
                "--disable-tls-checks")
                    wpscan_ssl="--disable-tls-checks"
                    recon_wpscan
                    ;;
            esac
            ;;
        "VERBOSE")
            msg="pwnMENU > RECON > HTTP > WPSCAN > <b>VERBOSE</b>\n<small>(optional) enable or disable verbosity of WP-Scan output</small>"
            menu="$(pfx "N/A") no verbosity$lb$(pfx "-v") enable verbosity"
            result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    wpscan_verbose=""
                    recon_wpscan
                    ;;
                "-v")
                    wpscan_verbose="-v"
                    recon_wpscan
                    ;;
            esac
            ;;
        "GEN")
            if [ "$wpscan_url" == "" ]; then
                rf_msg "$(pfx "ERROR") you have not set the necessary settings - you must set at least a URL"
                recon_wpscan
            else
                payload="wpscan --url $wpscan_url"
                if [ "$wpscan_ssl" != "" ]; then        payload="$payload $wpscan_ssl"; fi
                if [ "$wpscan_verbose" != "" ]; then    payload="$payload $wpscan_verbose"; fi
                if [ "$wpscan_threads" != "" ]; then    payload="$payload $wpscan_threads"; fi
                if [ "$wpscan_useragent" != "" ]; then  payload="$payload $wpscan_useragent"; fi
                if [ "$wpscan_user" != "" ]; then       payload="$payload $wpscan_user"; fi
                if [ "$wpscan_passlist" != "" ]; then   payload="$payload $wpscan_passlist"; fi
                if [ "$wpscan_enum" != "" ]; then       payload="$payload $wpscan_enum"; fi
                if [ "$wpscan_output" != "" ]; then     payload="$payload $wpscan_output"; fi
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") $1 WP-Scan command copied to the clipboard."
                exit 0
            fi
            recon_wpscan
            ;;
        "BACK")
            menu_recon
            ;;
    esac
}

wpscan_enum()
{
    msg="pwnMENU > RECON > HTTP > WPSCAN > <b>ENUM</b>\n<small>(optional) set custom enumeration options</small>"
    menu="$(pfx "BACK") go back ...$lb$lbrk$lb$(pfx "N/A") don't change\n<small>use default enumeration settings</small>$lb$(pfx "PLUGINS") $wpscan_enum_plug\n<small>set plugin enumeration level</small>$lb$(pfx "THEMES") $wpscan_enum_theme\n<small>set themes enumeration level</small>$lb$(pfx "TIMTHUMB") $wpscan_enum_tt\n<small>enable/disable Timthumb</small>$lb$(pfx "CONFBK") $wpscan_enum_cb\n<small>enable/disable config backups enumeration</small>$lb$(pfx "DBEXP") $wpscan_enum_dbe\n<small>enable/disable db exports enumeration</small>$lb$(pfx "USERID") $wpscan_enum_uid\n<small>set user ID range to check (default = 1-10)</small>$lb$(pfx "MEDIAID") $wpscan_enum_mid\n<small>set media ID range to check (default = 1-15)</small>$lb$lbrk$lb$(pfx "SAVE") save enumeration options"
    result=$(echo -e "$menu" | rf "ENUM" "$msg" 12)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "BACK")
            recon_wpscan
            ;;
        "$lbrk")
            recon_wpscan
            ;;
        "N/A")
            sqlmap_enum=""
            recon_wpscan
            ;;
        "PLUGINS")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>PLUGINS</b>\n<small>(optional) disable or set plugin enumeration options</small>"
            menu="$(pfx "N/A") no plugins$lb$(pfx "vp") vulnerable plugins$lb$(pfx "ap") all plugins$lb$(pfx "p") popular plugins"
            result=$(echo -e "$menu" | rf "PLUGINS" "$msg" 4)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_plug=""
            else
                wpscan_enum_plug="$result"
            fi
            wpscan_enum
            ;;
        "THEMES")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>THEMES</b>\n<small>(optional) disable or set themes enumeration options</small>"
            menu="$(pfx "N/A") no themes$lb$(pfx "vt") vulnerable themes$lb$(pfx "at") all themes$lb$(pfx "t") popular themes"
            result=$(echo -e "$menu" | rf "THEMES" "$msg" 4)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_theme=""
            else
                wpscan_enum_theme="$result"
            fi
            wpscan_enum
            ;;
        "TIMTHUMB")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>TIMTHUMB</b>\n<small>(optional) disable or enable timthumb enumeration option</small>"
            menu="$(pfx "N/A") disable timthumb enumeration$lb$(pfx "tt") enable timthumb enumeration"
            result=$(echo -e "$menu" | rf "TIMTHUMB" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_tt=""
            else
                wpscan_enum_tt="$result"
            fi
            wpscan_enum
            ;;
        "CONFBK")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>CONFBK</b>\n<small>(optional) disable or enable config backups enumeration option</small>"
            menu="$(pfx "N/A") disable config backups enumeration$lb$(pfx "cb") enable config backups enumeration"
            result=$(echo -e "$menu" | rf "CONFBK" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_cb=""
            else
                wpscan_enum_cb="$result"
            fi
            wpscan_enum
            ;;
        "DBEXP")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>DBEXP</b>\n<small>(optional) disable or enable database exports enumeration option</small>"
            menu="$(pfx "N/A") disable database exports enumeration$lb$(pfx "dbe") enable database exports enumeration"
            result=$(echo -e "$menu" | rf "DBEXP" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_dbe=""
            else
                wpscan_enum_dbe="$result"
            fi
            wpscan_enum
            ;;
        "USERID")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>USERID</b>\n<small>(optional) disable or set user ID range enumeration option</small>"
            menu="$(pfx "N/A") disable user ID enumeration$lb$(pfx "u") enable user ID enumeration"
            result=$(echo -e "$menu" | rf "USERID" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_uid=""
            else
                msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>USERID</b>\n<small>enter user ID range to enumerate (default = 1-10)</small>"
                range=$(echo '' | rf "USERID" "$msg" 0)
                wpscan_enum_uid="$result${range}"
            fi
            wpscan_enum
            ;;
        "MEDIAID")
            msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>MEDIAID</b>\n<small>(optional) disable or set media ID range enumeration option</small>"
            menu="$(pfx "N/A") disable media ID enumeration$lb$(pfx "m") enable media ID enumeration"
            result=$(echo -e "$menu" | rf "MEDIAID" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            if [ "$result" = "N/A" ]; then
                wpscan_enum_mid=""
            else
                msg="pwnMENU > RECON > HTTP > WPSCAN > ENUM > <b>MEDIAID</b>\n<small>enter media ID range to enumerate (default = 1-15)</small>"
                range=$(echo '' | rf "MEDIAID" "$msg" 0)
                wpscan_enum_mid="$result${range}"
            fi
            wpscan_enum
            ;;
        "SAVE")
            wpscan_enum="-e"
            if [ "$wpscan_enum_plug" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_plug"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_plug"
                fi
            fi
            if [ "$wpscan_enum_theme" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_theme"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_theme"
                fi
            fi
            if [ "$wpscan_enum_tt" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_tt"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_tt"
                fi
            fi
            if [ "$wpscan_enum_cb" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_cb"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_cb"
                fi
            fi
            if [ "$wpscan_enum_dbe" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_dbe"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_dbe"
                fi
            fi
            if [ "$wpscan_enum_uid" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_uid"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_uid"
                fi
            fi
            if [ "$wpscan_enum_mid" != "" ]; then
                if [ "$wpscan_enum" != "-e" ]; then
                    wpscan_enum="$wpscan_enum,$wpscan_enum_mid"
                else
                    wpscan_enum="$wpscan_enum $wpscan_enum_mid"
                fi
            fi
            recon_wpscan
            ;;
    esac
}

wpscan_userlist()
{
    if [ "$curr_dir" == "" ]; then
        curr_dir="$wordlists_dir"
    fi
    folders=$(echo -e "$(pfx -n "BACK") $curr_dir\n$lbrk"; ls -1 $curr_dir)
	result=$(echo -ne "$folders" | rf "USERLIST")
    result=$(echo $result | awk '{print $1}')
	case $result in
        "BACK")
            curr_dir=$(dirname $curr_dir)
            wpscan_userlist
            ;;
        "$lbrk")
            wpscan_userlist
            ;;
        *)
            if [ "$result" != "" ]; then
                if [ "$curr_dir" == "/" ]; then
                    curr_dir="/$result"
                else
                    curr_dir="$curr_dir/$result"
                fi
                if [ -d "$curr_dir" ]; then
                    wpscan_userlist
                else
                    wpscan_ulist="$curr_dir"
                    wpscan_user="-U $wpscan_ulist"
                    rf_msg "$(pfx -n "INFO") WPscan userlist set to '$wpscan_ulist'."
                    curr_dir=""
                    recon_wpscan
                fi
            else
                recon_wpscan
            fi
            ;;
    esac
}

wpscan_passlist()
{
    if [ "$curr_dir" == "" ]; then
        curr_dir="$wordlists_dir"
    fi
    folders=$(echo -e "$(pfx -n "BACK") $curr_dir\n$(pfx -n "DEFAULT") $def_pass_wordlist\n$lbrk"; ls -1 $curr_dir)
	result=$(echo -ne "$folders" | rf "PASSLIST")
    result=$(echo $result | awk '{print $1}')
	case $result in
        "BACK")
            curr_dir=$(dirname $curr_dir)
            wpscan_passlist
            ;;
        "DEFAULT")
            wpscan_passlist="-P $def_pass_wordlist"
            rf_msg "$(pfx -n "INFO") WPscan passlist set to '$def_pass_wordlist'."
            recon_wpscan
            ;;
        "$lbrk")
            wpscan_passlist
            ;;
        *)
            if [ "$result" != "" ]; then
                if [ "$curr_dir" == "/" ]; then
                    curr_dir="/$result"
                else
                    curr_dir="$curr_dir/$result"
                fi
                if [ -d "$curr_dir" ]; then
                    wpscan_passlist
                else
                    passlist="$curr_dir"
                    wpscan_passlist="-P $passlist"
                    rf_msg "$(pfx -n "INFO") WPscan passlist set to '$passlist'."
                    curr_dir=""
                    recon_wpscan
                fi
            else
                recon_wpscan
            fi
            ;;
    esac
}


recon_sqlmap()
{
    app="sqlmap"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_recon
        break
    fi
    if [ "$sqlmap_url" == "" ]; then
        sqlmap_url="http://$target_ip/"
    fi
    msg="pwnMENU > RECON > HTTP > <b>SQLMAP</b>\n<small>SQLmap checks target webserver for known misconfigurations that can lead to exploitation</small>"
    menu="$(pfx "URL") $sqlmap_url\nURL to scan with SQLmap$lb$(pfx "DETECT") $sqlmap_detect\n(optional) tweak detection levels for more results$lb$(pfx "BATCH") $sqlmap_batch\n(optional) enable non-interactive mode$lb$(pfx "ENUM") $sqlmap_enum\n(optional) control SQLmap enumeration$lb$(pfx "SHELLS") $sqlmap_shell\n(optional) attempt to spawn shells or run OS commands$lb$(pfx "USERAGNT") $sqlmap_useragent\n(optional) change user-agent to send with request$lb$(pfx "THREADS") $sqlmap_threads\n(optional) change amount of threads used$lb$(pfx "SSL") $sqlmap_ssl\n(optional) enable or disable the forcing of SSL$lb$(pfx "VERBOSE") $sqlmap_verbose\n(optional) change verbosity level of output$lb$lbrk$lb$(pfx "GEN") generate SQLmap command$lb$(pfx "BACK") go back..."
    result=$(echo -e "$menu" | rf "SQLMAP" "$msg" 12)
    result=$(echo $result | awk '{print $1}')
    case $result in
        "URL")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>URL</b>\n<small>enter or select the URL to be scanned with SQLmap\n\n<b>NOTE:</b> you need to aim SQLmap at a specific link for better results (e.g. '?option=' urls or forms that may be injectable</small>"
            urls="$(pfx "TARGET") http://$target_ip/"
            result=$(echo -e "$urls" | rf "URL" "$msg" 1)
            if [ "$(echo $result | awk '{print $2}')" == "❯❯" ]; then
                sqlmap_url=$(echo $result | awk '{print $3}')
            else
                sqlmap_url=$(echo $result | awk '{print $1}')
            fi
            recon_sqlmap
            ;;
        "DETECT")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>DETECT</b>\n<small>(optional) tweak detection level and risk settings to increase chances (both default to 1) </small>"
            menu="$(pfx "N/A") leave default$lb$(pfx "--level") modify level setting (1-5)$lb$(pfx "--risk") modify risk setting (1-3)"
            result=$(echo -e "$menu" | rf "OUTPUT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_detect=""
                    recon_sqlmap
                    ;;
                "--level")
                    msg="pwnMENU > RECON > HTTP > SQLMAP > OUTPUT > <b>--level</b>\n<small>enter a number between 1-5 (default 1)</small>"
                    level=$(echo '' | rf "LEVEL" "$msg" 0)
                    if [ $level -lt 1 ] || [ $level -gt 5 ]; then
                        rf_msg "$(pfx "ERROR") incorrect value for level - must be between 1 - 5"
                        recon_sqlmap
                    fi
                    if [ "$sqlmap_detect" == "" ]; then
                        sqlmap_detect="--level $level"
                    elif [[ "$sqlmap" != *--level* ]]; then
                        sqlmap_detect="$sqlmap_detect --level $level"
                    fi
                    recon_sqlmap
                    ;;
                "--risk")
                    msg="pwnMENU > RECON > HTTP > SQLMAP > OUTPUT > <b>--risk</b>\n<small>enter a number between 1-3 (default 1)</small>"
                    level=$(echo '' | rf "RISK" "$msg" 0)
                    if [ $level -lt 1 ] || [ $level -gt 3 ]; then
                        rf_msg "$(pfx "ERROR") incorrect value for risk - must be between 1 - 3"
                        recon_sqlmap
                    fi
                    if [ "$sqlmap_detect" == "" ]; then
                        sqlmap_detect="--risk $level"
                    elif [[ "$sqlmap" != *--risk* ]]; then
                        sqlmap_detect="$sqlmap_detect --risk $level"
                    fi
                    recon_sqlmap
                    ;;
            esac
            ;;
        "BATCH")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>BATCH</b>\n<small>(optional) enabling --batch makes SQLmap answer the questions it asks with default, making it non-interactive</small>"
            menu="$(pfx "N/A") don't use batch mode$lb$(pfx "--batch") use batch mode"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_batch=""
                    recon_sqlmap
                    ;;
                "--batch")
                    sqlmap_batch="--batch"
                    recon_sqlmap
                    ;;
            esac
            ;;
        "ENUM")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>ENUM</b>\n<small>(optional) set custom enumeration options</small>"
            menu="$(pfx "BACK") go back ...$lb$lbrk$lb$(pfx "N/A") use default enumeration settings$lb$(pfx "--all") enumerate all the things!$lb$(pfx "--banner") grab DBMS banner$lb$(pfx "--current-user") grab DBMS current user$lb$(pfx "--current-db") grab DBMS current database$lb$(pfx "--hostname") grab DBMS server hostname$lb$(pfx "--is-dba") check DBMS current user is DB admin$lb$(pfx "--users") enumerate DBMS users$lb$(pfx "--passwords") enumerate DBMS user password hashes$lb$(pfx "--privileges") enumerate DBMS user privileges$lb$(pfx "--roles") enumerate DBMS user roles$lb$(pfx "--schema") enumerate DBMS schema$lb$(pfx "--dump-all") dump DBMS database table entries"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg")
            result=$(echo $result | awk '{print $1}')
            case $result in
                "BACK")
                    recon_sqlmap
                    ;;
                "$lbrk")
                    recon_sqlmap
                    ;;
                "N/A")
                    sqlmap_enum=""
                    recon_sqlmap
                    ;;
                "--all")
                    sqlmap_enum="--all"
                    recon_sqlmap
                    ;;
                "--banner")
                    sqlmap_chk_enum "--banner"
                    ;;
                "--current-user")
                    sqlmap_chk_enum "--current-user"
                    ;;
                "--current-db")
                    sqlmap_chk_enum "--current-db"
                    ;;
                "--hostname")
                    sqlmap_chk_enum "--hostname"
                    ;;
                "--is-dba")
                    sqlmap_chk_enum "--is-dba"
                    ;;
                "--users")
                    sqlmap_chk_enum "--users"
                    ;;
                "--passwords")
                    sqlmap_chk_enum "--passwords"
                    ;;
                "--privileges")
                    sqlmap_chk_enum "--privileges"
                    ;;
                "--roles")
                    sqlmap_chk_enum "--roles"
                    ;;
                "--schema")
                    sqlmap_chk_enum "--schema"
                    ;;
                "--dump-all")
                    sqlmap_chk_enum "--dump-all"
                    ;;
            esac
            ;;
        "SHELLS")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>SHELLS</b>\n<small>(optional) try to spawn shells or run an OS command on the target</small>"
            menu="$(pfx "N/A") no shells or command$lb$(pfx "--os-cmd") run an OS command$lb$(pfx "--os-shell") interactive OS shell$lb$(pfx "--priv-esc") attempt database user privilege escalation$lb$(pfx "--os-pwn") prompt for OOB / Meterpreter / VNC shell$lb$(pfx "--sql-shell") interactive SQL shell"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 6)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_shell=""
                    recon_sqlmap
                    ;;
                "--os-cmd")
                    msg="pwnMENU > RECON > HTTP > SQLMAP > SHELLS > <b>--os-cmd</b>\n<small>enter shell command to run</small>"
                    cmd=$(echo '' | rf "CMD" "$msg" 0)
                    sqlmap_shell="--os-cmd=\"$cmd\""
                    recon_sqlmap
                    ;;
                "--os-shell")
                    sqlmap_shell="--os-shell"
                    recon_sqlmap
                    ;;
                "--priv-esc")
                    sqlmap_shell="--os-shell --priv-esc"
                    recon_sqlmap
                    ;;
                "--os-pwn")
                    sqlmap_shell="--os-pwn"
                    recon_sqlmap
                    ;;
                "--sql-shell")
                    sqlmap_shell="--sql-shell"
                    recon_sqlmap
                    ;;
            esac
            ;;
        "USERAGNT")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>USERAGNT</b>\n<small>(optional) set the User-Agent property sent with each request</small>"
            menu="$(pfx "N/A") use default user-agent$lb$(pfx "--mobile") imitate smartphone user-agent$lb$(pfx "--random-agent") set custom user-agent"
            result=$(echo -e "$menu" | rf "USERAGNT" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_useragent=""
                    recon_sqlmap
                    ;;
                "--mobile")
                    sqlmap_useragent="--mobile"
                    recon_sqlmap
                    ;;
                "--random-agent")
                    sqlmap_useragent="--random-agent"
                    recon_sqlmap
                    ;;
            esac
            ;;
        "THREADS")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>THREADS</b>\n<small>(optional) set the threads used (default = 1)</small>"
            menu="$(pfx "N/A") single thread (a.k.a. default)$lb$(pfx "--threads") set amount of threads"
            result=$(echo -e "$menu" | rf "THREADS" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_threads=""
                    recon_wpscan
                    ;;
                "--threads")
                    msg="pwnMENU > RECON > HTTP > WPSCAN > USERAGNT > <b>--threads</b>\n<small>enter threads to use (default = 1)</small>"
                    threads=$(echo '' | rf "THREADS" "$msg" 0)
                    sqlmap_threads="--threads=$threads"
                    recon_wpscan
                    ;;
            esac
            ;;
        "SSL")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>SSL</b>\n<small>(optional) force SSL</small>"
            menu="$(pfx "N/A") leave ssl default$lb$(pfx "--force-ssl") force usage of ssl"
            result=$(echo -e "$menu" | rf "SSL" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_ssl=""
                    recon_sqlmap
                    ;;
                "--force-ssl")
                    sqlmap_ssl="--force-ssl"
                    recon_sqlmap
                    ;;
            esac
            ;;
        "VERBOSE")
            msg="pwnMENU > RECON > HTTP > SQLMAP > <b>VERBOSE</b>\n<small>(optional) set the verbosity of SQLmap output</small>"
            menu="$(pfx "N/A") no verbosity$lb$(pfx "-v") set level of verbosity (default = 1)"
            result=$(echo -e "$menu" | rf "VERBOSE" "$msg" 3)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    sqlmap_verbose=""
                    recon_sqlmap
                    ;;
                "-v")
                    msg="pwnMENU > RECON > HTTP > SQLMAP > VERBOSE > <b>-v</b>\n<small>enter verbosity level (default = 1)</small>"
                    level=$(echo '' | rf "VERBOSE" "$msg" 0)
                    sqlmap_verbose="-v $level"
                    recon_sqlmap
                    ;;
            esac
            ;;
        "GEN")
            if [ "$sqlmap_url" == "" ]; then
                rf_msg "$(pfx "ERROR") you have not set the necessary settings - you must set at least a URL"
                recon_sqlmap
            else
                payload="sqlmap -u $sqlmap_url"
                if [ "$sqlmap_ssl" != "" ]; then        payload="$payload $sqlmap_ssl"; fi
                if [ "$sqlmap_verbose" != "" ]; then    payload="$payload $sqlmap_verbose"; fi
                if [ "$sqlmap_threads" != "" ]; then    payload="$payload $sqlmap_threads"; fi
                if [ "$sqlmap_enum" != "" ]; then       payload="$payload $sqlmap_enum"; fi
                if [ "$sqlmap_shell" != "" ]; then      payload="$payload $sqlmap_shell"; fi
                if [ "$sqlmap_useragent" != "" ]; then  payload="$payload $sqlmap_useragent"; fi
                if [ "$sqlmap_detect" != "" ]; then     payload="$payload $sqlmap_detect"; fi
                if [ "$sqlmap_batch" != "" ]; then      payload="$payload $sqlmap_batch"; fi
                echo -ne $payload | xclip -sel clip
                rf_msg "$(pfx -n "INFO") SQLmap command copied to the clipboard."
                exit 0
            fi
            recon_sqlmap
            ;;
        "BACK")
            menu_recon
            ;;
    esac
}

sqlmap_chk_enum()
{
    switch="$1"
    if [ "$sqlmap_enum" == "--all" ]; then
        rf_msg "$(pfx -n "ERROR") SQLmap enumeration already set to --all, no other settings are necessary."
    else
        if [ "$sqlmap_enum" != "" ]; then
            if [[ "$sqlmap_enum" == *$switch* ]]; then
                msg="pwnMENU > RECON > HTTP > SQLMAP > ENUM > <b>$switch</b>\n<small>this switch is already enabled, do you wish to remove it?</small>"
                answer=$(echo -e "yes${lb}no" | rf "VERBOSE" "$msg" 2)
                if [ "$answer" == "yes" ]; then
                    sqlmap_enum="$(echo $sqlmap_enum | sed "s/$switch//g")"
                    rf_msg "$(pfx -n "INFO") SQLmap enumeration switch $switch removed from payload."
                fi
            else
                sqlmap_enum="$sqlmap_enum $switch"
            fi
        else
            sqlmap_enum="$switch"
        fi
    fi
    recon_sqlmap
}

recon_smb()
{
    rf_msg "$(pfx "INFO") coming soon... watch this space!"
}
