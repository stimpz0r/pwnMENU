#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - the pentester's "quick menu" toolbox
################### #### ## #  #    #
# based on "dmenu_pentest" by Cipher007 (https://github.com/Cipher7/dmenu_pentest)
# modified, renamed and extended by stimpz0r (12-2021)
# rofi theme originally by adi1090x, modified for use on pwnTOOLS by stimpz0r (colour theme based on HTB VSCode theme)
#
# this script originally helped stabilize shells, spawn shells with oneliners, spawn tty shells, some msfvenom 
# magic and basic mimikatz commands... a base to build off... ;)
#
# the basis of this script is not to actually run the commands for you - it will place the necessary command syntax in your clipboard so 
# you can paste it wherever you need it. simply bind it to a keyboard shortcut and you can call it whenever you need it!
#
# the only caveat to the standard operation rule is the shell stabilization - you need to start pwnMENU with the correct window active so 
# it can paste the relevant commands in the terminal. 
#
# this is still a work in progress - as of now the "brute" menu is not implemented (will include tools for brute-forcing passwords and 
# services), and there will be more features added / improved in the future.
#
# before running, set the options below (up to the point where it states "DO NOT EDIT BELOW VARIABLES") and make sure the paths are 
# correct before executing. i have also uploaded "pwnTOOLS" to my github - this is the skeleton of my HTTPD server and is compatible
# with this script. you are most welcome to add tools in here and 
#
# pwnMENU features:
##################### ## #
#
# > added the "shells" menu 
#   > get the command to start a netcat listener based on the target port settings
#   > spawn shells using various methods dependant on the target OS
#   > spawn TTY via Python to semi-stabilize the shell (if full stabilization is not possible)
#   > stabilizing shells will grab the correct tty dimensions from stty and sets them, will also disable bash history and is ZSH compatible!
#   > msfvenom section has been completely rewritten to simplify and extend even further
# > added "privesc" menu determined by target OS / arch - e.g. select a Linux target and get Linux privesc tools!
#   > outputs a command that will download the privesc file from the Python HTTPD server controlled by pwnMENU (and execute)
#   > added support for linPEAS, Linux Smart Enumeration, LinEnum & suid3num for Linux targets
#   > added support for winPEAS, Seatbelt, PowerView, PowerUp, Invoke-Kerberoast, LaZagne & Mimikatz for Windows targets
# > added "recon" menu to help enumerate targets by building command line syntax for enumeration applications
#   > added support for NMAP, FeroxBuster, Nikto, CMSeeK, WPScan & SQLMap
# > added "tools" menu
#   > added the ability to start and stop both a HTTPD and SMBD server using Python (SMBD server requires Impacket "smbserver.py") to help 
#     upload tools to the target, or even exfiltrate data from the target (using SMBD).
#   > added "upload" menu to allow downloading handy tools hosted on the HTTPD to the target via platform-specific methods
# > added "exploit" menu 
#   > added a front-end to searchsploit, that lets you search (in-menu) for exploits, locally mirror the exploit as a cipboard command,
#     or even run an NMAP xml scan through searchsploit to check for exploitable services (requires nmap to be used with -oX output and -sV)
#   > added an "upload" menu to allow downloading exploits hosted on the HTTPD to the target via platform-specific methods.

#

# home_dir >> home directory
###### #  #
#
# the 'home_dir' variable sets the base folder for pwnMENU - this is where all data and themes are saved.

home_dir="$HOME/pwnMENU"

# target setup >> default configuration
######## #  #
#
# below are the "default" settings for target OS / arch / etc. they will be overwritten if 'target_cfg_file' exists and
# set appropriately to the configured 'TARGET_OS' and 'TARGET_ARCH' set in that file.
#
# the 'target_cfg_file' should contain - "TARGET_IP TARGET_OS TARGET_ARCH" (spaces seperating), this can be modified and
# overwritten in the 'TARGET' menu off the main menu.

target_cfg_file="$home_dir/target.cfg"

target_os="linux"                               # default 'target_os' is assumed "linux"
target_arch="x64"                               # default 'target_arch' is assumed "x64"
dl_method="curl"                                # linux = curl / wget | windows = certutil / powershell
shell="/bin/bash"                               # default shell spawned is "/bin/bash"
spawner="bash"                                  # default shell spawner is "bash"
msfv_target="linux"                             # default MSFVenom target should be the same as 'target_os'
msfv_arch="x64"                                 # default MSFVenom arch should be the same as 'target_arch'
msfv_type="shell"                               # default MSFVenom type is a staged "shell"
msfv_conn="reverse_tcp"                         # default MSFVenom connection type is "reverse_tcp"
msfv_payload="linux/x64/shell/reverse_tcp"      # default MSFVenom should be target, arch, type & conn combined

# attack ip & port >> defaults
###### #  #
#
# 'def_ip' can be set to either an IP address, device name (non-local) such as "tun0" for to use a VPN IP or "PUBLIC" for your
# public facing IP... 'def_port' can be anything between 1 and 65535 (the script will error if you set it incorrectly)

def_ip="tun0"
def_port=1337

# the next two relate to IP history - if enabled, the file will be chmodded 600 so it is only readable/writable by yourself.
# to enable IP history simply set 'ip_history' to '1', or '0' for off. you can change the filename and it's path by modifying
# 'ip_history_list'

# WARNING - disabling this feature after using it will destroy the history file, if you want to keep them then back them up
# or rename them before changing the setting.

ip_history=1
ip_history_list="$home_dir/.ip_history"

# as above, the below relate to port history... same rules apply!

port_history=1
port_history_list="$home_dir/.port_history"

# HTTPD >> defaults
##### #  #
#
# these can help make spawning this simple python HTTPD a lot easier... the 'httpd_root_dir' should point to a folder that
# hosts all the tools you wish to be able to upload to the target.

httpd_root_dir="$HOME/hacktools"
httpd_bind_ip="$def_ip"             # this sets the default bind ip to also be the same as 'def_ip', uses the same format too!
httpd_def_port=8080

# SMBD >> defaults
##### #  #
#
# these can help make spawning the Impacket SMBD server a lot easier... the 'smbd_root_dir' should point to a folder that
# hosts all the tools you wish to be able to upload to the target (or alternatively just point it to 'httpd_root_dir').

smbd_root_dir="$httpd_root_dir"     # this sets the default directory to be the same as the HTTPD server (tools access)
smbd_bind_ip="$def_ip"              # this sets the default bind ip to also be the same as 'def_ip', uses the same format too!
smbd_def_share="tools"              # this is the default share name for the SMBD server... it can be whatever you want! ;)

# NMAP >> defaults
##### #  #
#
# default shell spawner settings, dependant on OS - as with other platform-dependant settings, these assume
# the default platform is 'linux'

nmap_scan_type="-sS"
nmap_hostdisc="ON"

# wordlists >> defaults
##### #  #
#
# default shell spawner settings, dependant on OS - as with other platform-dependant settings, these assume
# the default platform is 'linux'

wordlists_dir="/usr/share/wordlists"
def_http_wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
def_pass_wordlist="/usr/share/wordlists/rockyou.txt"

# searchsploit >> temp file name
##### #  #
#
# this is the name of the file saved when using searchsploit menu - this is used to build the menu to show your search
# results - it can be left as is, or modified. this file gets rm'd at start up of the script.

ss_temp_file="$home_dir/.ssploit.tmp"

# MSFVenom >> list filenames
######## #  #
#
# the below filenames is where pwnMENU stores the relevant lists... these can be updated to the latest from the
# 'msfvenom' menu

msfv_payload_list="$home_dir/.msfv_payload.lst"
msfv_arch_list="$home_dir/.msfv_arch.lst"
msfv_format_list="$home_dir/.msfv_format.lst"

### DO NOT EDIT BELOW VARIABLES

lb='\x0f'
lbrk="------------------------- ---- -- -"

ip=""
port=0

ips=""
ports=""

if [ -f "$ss_temp_file" ]; then
    rm $ss_temp_file
fi

target_set_defaults()
{
    msfv_target="$target_os"
    msfv_arch="$target_arch"
    msfv_type="shell"
    msfv_conn="reverse_tcp"
    if [ "$target_os" == "windows" ] && [ "$target_arch" == "x86" ]; then
        msfv_payload="$target_os/shell/reverse_tcp"
    else
        msfv_payload="$target_os/$target_arch/shell/reverse_tcp"
    fi
    if [ "$target_os" == "linux" ]; then
        dl_method="curl"
        shell="/bin/bash"
        spawner="bash"
    elif [ "$target_os" == "windows" ]; then
        dl_method="powershell"
        shell="powershell.exe"
        spawner="powershell"
    fi
}

if [ -f $target_cfg_file ]; then
    target_ip="$(cat $target_cfg_file | awk '{print $1}')"
    target_os="$(cat $target_cfg_file | awk '{print $2}')"
    target_arch="$(cat $target_cfg_file | awk '{print $3}')"
    target_set_defaults
fi

main()
{
	menu="$(pfx -n "RECON") reconnaissance (enumeration)\n<small>scanning tools to help you find your way in!</small>$lb$(pfx -n "TOOLS") tools\n<small>HTTPD / SMB servers and uploading tools to remote target</small>$lb$(pfx -n "BRUTE") brute-force cracks/attacks\n<small>cracking of hashes / brute-force attacks</small>$lb$(pfx -n "PRIVESC") privilege escalation\n<small>potential methods to escalate your privileges on the target system</small>$lb$(pfx -n "EXPLOIT") exploits\n<small>searchsploit and locally hosted exploit uploads (via HTTPD)</small>$lb$(pfx -n "SHELL") shells\n<small>spawn, stabilize and generate shells</small>$lb$lbrk$lb$(pfx -n "TARGET") $target_ip | $target_os | $target_arch\n<small>set, remove or change the current target setup</small>"
	msg="<b>pwnMENU</b> >> by stimpz0r (2021)\n<small>select from the following options:</small>"
	result=$(echo -ne "$menu" | rf "pwnMENU" "$msg" 11)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"RECON")
			menu_recon
			;;
		"BRUTE")
			menu_brute
			;;
		"PRIVESC")
			menu_privesc
			;;
		"EXPLOIT")
			menu_exploit
			;;
		"SHELL")
			menu_shells
			;;
		"TOOLS")
			menu_tools
			;;
		"TARGET")
			menu_target
			;;
	esac
}

menu_target()
{
	menu="$(pfx -n "IP") $new_target_ip\n<small>(current = $target_ip) change the target IP address</small>$lb$(pfx -n "OS") $new_target_os\n<small>(current = $target_os) change the target OS</small>$lb$(pfx -n "ARCH") $new_target_arch\n<small>(current = $target_arch) change the target OS architecture</small>$lb$lbrk$lb$(pfx -n "SET") $target_ip | $target_os | $target_arch\n<small>save the above changes</small>$lb$(pfx -n "RESET") reset target\n<small>removes the target configuration</small>$lb$(pfx -n "COPYIP") $target_ip \n<small>copies the target IP to the clipboard</small>"
	msg="pwnMENU > <b>TARGET</b>\n<small>select from the following options:</small>"
	result=$(echo -ne "$menu" | rf "TARGET" "$msg" 11)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"IP")
            old_ip="$ip"
            if [ "$target_ip" != "" ]; then
                ips="$(pfx "CURRENT") $target_ip"
            fi
            clip=$(xclip -o)
            if [[ "$clip" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]] && [ "$ips" != "" ]; then
                ips="$ips\n$(pfx "CLIPBRD") $clip"
            elif [[ "$clip" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]] && [ "$ips" == "" ]; then
                ips="$(pfx "CLIPBRD") $clip"
            fi
            unset clip
            if [ "$target_ip" != "" ] && [ "$ips" != "" ]; then
                ips="$ips\n$(pfx "SAVED") $target_ip"
            elif [ "$target_ip" != "" ] && [ "$ips" == "" ]; then
                ips="$(pfx "SAVED") $(cat $target_ip_file)"
            fi
            set_ip -t
            new_target_ip="$ip"
            ip="$old_ip"
            menu_target
            ;;
		"OS")
			msg="pwnMENU > TARGET > <b>OS</b>\n<small>select the target OS (operating system):</small>"
            target_oss="linux${lb}windows"
			new_target_os=$(echo -ne "$target_oss" | rf "OS" "$msg" 2)
            menu_target
			;;
		"ARCH")
			msg="pwnMENU > TARGET > <b>ARCH</b>\n<small>select the target OS architecture:</small>"
            target_arches="x64${lb}x86"
			new_target_arch=$(echo -ne "$target_arches" | rf "ARCH" "$msg" 2)
            menu_target
			;;
		"SET")
            target_ip="$new_target_ip"
            target_os="$new_target_os"
            target_arch="$new_target_arch"
            echo -e "$target_ip $target_os $target_arch" > $target_cfg_file
            target_set_defaults
            rf_msg "$(pfx -n "INFO") target configuration has been saved."
            menu_target
			;;
		"RESET")
            if [ -f "$target_cfg_file" ]; then
                rm $target_cfg_file
                rf_msg "$(pfx -n "INFO") target configuration has been saved."
            else
                rf_msg "$(pfx -n "ERROR") target configuration not found, nothing done."
            fi
            menu_target
			;;
        "COPYIP")
            echo -ne $target_ip | xclip -sel clip
            rf_msg "$(pfx -n "INFO") target IP '$target_ip' copied to the clipboard."
            exit 0
            ;;
    esac
}

rf()
{
    header=$1
    msg="$(echo -e "$2")"
    lines=$3
    if [ "$msg" != "" ] && [ "$lines" != "" ]; then
        if [ "$header" == "SUDO" ]; then
            rofi -theme $home_dir/pwn.rasi -dmenu -p "$(pfx $header)" -markup-rows -sorting-method 'fzf' -selected-row 0 -theme-str "listview { lines: $lines; }" -sep '\x0f' -eh 2 -mesg "$msg" -password
        else
            rofi -theme $home_dir/pwn.rasi -dmenu -p "$(pfx $header)" -markup-rows -sorting-method 'fzf' -selected-row 0 -theme-str "listview { lines: $lines; }" -sep '\x0f' -eh 2 -mesg "$msg"
        fi
    elif [ "$lines" != "" ] && [ "$msg" == "" ]; then
        rofi -theme $home_dir/pwn.rasi -dmenu -p "$(pfx $header)" -selected-row 0 -sorting-method 'fzf' -theme-str "listview { lines: $lines; }"
    elif [ "$lines" == "" ] && [ "$msg" != "" ]; then
        rofi -theme $home_dir/pwn.rasi -dmenu -p "$(pfx $header)" -markup-rows -selected-row 0 -sorting-method 'fzf' -sep '\x0f' -eh 2 -mesg "$msg"
    elif [ "$lines" == "" ] && [ "$msg" == "" ]; then
        rofi -theme $home_dir/pwn.rasi -dmenu -p "$(pfx $header)" -selected-row 0 -sorting-method 'fzf'
    fi
}

rf_msg()
{
	rofi -theme $home_dir/pwn_msg.rasi -e "$@"
}

notify()
{
    msg="$1"
    echo "msg = $msg"
    bash -c "notify-send "pwnMENU" '$msg' -t 5000"
}

pfx()
{
    if [ "$1" == "-n" ]; then
        echo $2 | awk '{printf "%s ❯❯", $1}'
    else
        echo $1 | awk '{printf "%8s ❯❯", $1}'
    fi
}

cmd()
{
	xte "str $1"
	sleep 0.5
	xte "key Return"
}

ctrl()
{
	xte "keydown Control_L" "key $1" "keyup Control_L"
}

ctrl_shift()
{
	xte "keydown Control_L" "keydown Shift_L" "key $1" "keyup Control_L" "keyup Shift_L"
}

get_ips()
{
    if [ "$1" == "-h" ]; then
        use_history=0
    else
        use_history=1
    fi

    ips="$(ip -o addr show scope global | awk '/^[0-9]:/{printf "%8s ❯❯ %s\n", $2, $4}' | sort | cut -f1 -d '/')"
    ips="$ips\n$(pfx "PUBLIC") $(dig +short myip.opendns.com @resolver1.opendns.com)"

    clip=$(xclip -o)
    if [[ "$clip" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]]; then
        ips="$ips\n$(pfx "CLIPBRD") $clip"
    fi
    unset clip

    check_default=$(echo -e "$ips" | grep "DEFAULT" | wc -l)
    if [ "$def_ip" != "" ] && [ $check_default -eq 0 ]; then
        if [ "$def_ip" == "$(echo -e "$ips" | grep "$def_ip" | awk '{print $1}')" ]; then
            if [ "$ip" == "" ]; then
                ip="$(echo -e "$ips" | grep "$def_ip" | awk '{print $3}')"
                ips="$(pfx "DEFAULT") $ip\n$ips"
            else
                ips="$(pfx "DEFAULT") $(echo -e "$ips" | grep "$def_ip" | awk '{print $3}')\n$ips"
            fi
        elif [[ "$def_ip" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]]; then
            if [ "$ip" == "" ]; then
                ip="$def_ip"
                ips="$(pfx "DEFAULT") $ip\n$ips"
            else
                ips="$(pfx "DEFAULT") $def_ip\n$ips"
            fi
        fi
    fi

    check_curr=$(echo -e "$ips" | grep "CURRENT" | wc -l)
    if [ $check_curr -eq 0 ] && [ "$ip" != "" ]; then
        ips="$(pfx "CURRENT") $ip\n$ips"
    elif [ $check_curr -eq 1 ] && [ $(echo -e "$ips" | grep "CURRENT" | awk '{print $3}') -ne $port ]; then
        ips="$(pfx "CURRENT") $ip\n$(echo -e "$ips" | grep -v "CURRENT")"
    fi


    if [ -f $ip_history_list ] && [ $ip_history -eq 1 ] && [ $use_history -eq 1 ]; then
        c=0
        ips=$(echo -e "$ips" | grep -v "HISTORY")
        while IFS= read -r curr_ip
        do
            let c++
            ips="$ips\n$(pfx "HISTORY$c") $curr_ip"
        done < "$ip_history_list"
    elif [ ! -f $ip_history_list ] && [ $ip_history -eq 1 ] && [ $use_history -eq 1 ]; then
        touch $ip_history_list
        chmod 600 $ip_history_list
        if [ "$ip" != "" ]; then
            echo -e "$ip" > $ip_history_list
        fi
    elif [ -f $ip_history_list ] && [ $ip_history -eq 0 ] && [ $use_history -eq 1 ]; then
        rm $ip_history_list
    fi
}

get_ports()
{
    if [ "$1" == "-h" ]; then
        use_history=0
    else
        use_history=1
    fi

    if [ $def_port -lt 1 ] || [ $def_port -gt 65535 ]; then
        rf_msg "$(pfx -n "ERROR") you have set an invalid port for 'def_port' - please choose a number between 1 and 65535"
        exit 1
    else
        check_default=$(echo -e "$ports" | grep "DEFAULT" | wc -l)
        if [ $def_port -ne 0 ] && [ $check_default -eq 0 ]; then
            ports="$(pfx "DEFAULT") $def_port\n$ports"
            if [ $port -eq 0 ]; then
                port=$def_port
            fi
        fi

        check_curr=$(echo -e "$ports" | grep "CURRENT" | wc -l)
        if [ $check_curr -eq 0 ] && [ "$port" != "" ]; then
            ports="$(pfx "CURRENT") $port\n$ports"
        elif [ $check_curr -eq 1 ] && [ "$(echo -e "$ports" | grep "CURRENT" | awk '{print $3}')" != "$port" ]; then
            ports="$(pfx "CURRENT") $port\n$(echo -e "$ports" | grep -v "CURRENT")"
        fi

        if [ -f $port_history_list ] && [ $port_history -eq 1 ] && [ $use_history -eq 1 ]; then
            c=0
            ports=$(echo -e "$ports" | grep -v "HISTORY")
            while IFS= read -r curr_port
            do
                let c++
                ports="$ports\n$(pfx "HISTORY$c") $curr_port"
            done < "$port_history_list"
        elif [ ! -f $port_history_list ] && [ $port_history -eq 1 ] && [ $use_history -eq 1 ]; then
            touch $port_history_list
            chmod 600 $port_history_list
            if [ "$port" != "" ]; then
                echo -e "$port" > $port_history_list
            fi
        elif [ -f $port_history_list ] && [ $port_history -eq 0 ] && [ $use_history -eq 1 ]; then
            rm $port_history_list
        fi
    fi
}

set_ip()
{
    if [ "$1" == "-h" ]; then
        use_history=0
        lines=6
    else
        use_history=1
        lines=9
    fi

    new_ip="$(echo -e "$ips" | rf "IP" "" $lines)"
    if [ "$(echo $new_ip | awk '{print $2}')" == "❯❯" ]; then
        new_ip=$(echo $new_ip | awk '{print $3}')
    fi

    if [[ "$new_ip" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]]; then
        if [ "$new_ip" != "$ip" ]; then
            ip="$new_ip"
            if [ -f $ip_history_list ] && [ $ip_history -eq 1 ] && [ $use_history -eq 1 ]; then
                hist_lines=$(cat $ip_history_list | wc -l)
                case $hist_lines in
                    0)
                        echo -e "$ip" > $ip_history_list
                    ;;
                    1)
                        if [ "$(cat $ip_history_list)" != "$ip" ]; then
                            echo -e "$ip\n$(cat $ip_history_list)" > $ip_history_list
                        fi
                    ;;
                    2)
                        if [ "$ip" == "$(cat $ip_history_list | grep $ip)" ] && [ "$ip" != "$(cat $ip_history_list | sed '1q;d')" ]; then
                            echo -e "$ip\n$(cat $ip_history_list | sed '1q;d')" > $ip_history_list
                        elif [ "$ip" != "$(cat $ip_history_list | grep $ip)" ]; then
                            echo -e "$ip\n$(cat $ip_history_list)" > $ip_history_list
                        fi
                    ;;
                    3)
                        if [ "$ip" == "$(cat $ip_history_list | grep $ip)" ] && [ "$ip" != "$(cat $ip_history_list | sed '1q;d')" ]; then
                            echo -e "$ip\n$(cat $ip_history_list | grep -v "$ip" | head -n 3)" > $ip_history_list
                        elif [ "$ip" != "$(cat $ip_history_list | grep $ip)" ]; then
                            echo -e "$ip\n$(head -n 2 $ip_history_list)" > $ip_history_list
                        fi
                    ;;
                esac
            fi
        fi
    else
        rf_msg "$(pfx "ERROR") the ip entered/selected is not valid. please try again."
    fi
}

set_port()
{
    if [ "$1" == "-h" ]; then
        use_history=0
        lines=2
    else
        use_history=1
        lines=5
    fi

    new_port="$(echo -e "$ports" | rf "PORT" "" $lines)"
    if [ "$(echo $new_port | awk '{print $2}')" == "❯❯" ]; then
        new_port=$(echo $new_port | awk '{print $3}')
    fi
    new_port=$(($new_port + 0))

    if [ $new_port -lt 1 ] || [ $new_port -gt 65535 ]; then
        rf_msg "$(pfx -n "ERROR") you have set an invalid port - please choose a number between 1 and 65535"
    else
        if [ $new_port -ne $port ]; then
            port=$new_port
            if [ -f $port_history_list ] && [ $port_history -eq 1 ] && [ $use_history -eq 1 ]; then
                hist_lines=$(cat $port_history_list | wc -l)
                case $hist_lines in
                    0)
                        echo -e "$port" > $port_history_list
                    ;;
                    1)
                        if [ "$(cat $port_history_list)" != "$port" ]; then
                            echo -e "$port\n$(cat $port_history_list)" > $port_history_list
                        fi
                    ;;
                    2)
                        if [ "$port" == "$(cat $port_history_list | grep $port)" ] && [ "$port" != "$(cat $port_history_list | sed '1q;d')" ]; then
                            echo -e "$port\n$(cat $port_history_list | sed '1q;d')" > $port_history_list
                        elif [ "$port" != "$(cat $port_history_list | grep $port)" ]; then
                            echo -e "$port\n$(cat $port_history_list)" > $port_history_list
                        fi
                    ;;
                    3)
                        if [ "$port" == "$(cat $port_history_list | grep $port)" ] && [ "$port" != "$(cat $port_history_list | sed '1q;d')" ]; then
                            echo -e "$port\n$(cat $port_history_list | grep -v "$port" | head -n 3)" > $port_history_list
                        elif [ "$port" != "$(cat $port_history_list | grep $port)" ]; then
                            echo -e "$port\n$(cat $port_history_list | head -n 2)" > $port_history_list
                        fi
                    ;;
                esac
            fi
        fi
    fi
}

app_exists()
{
    command -v $1
    return $?
}

# includes >> extend...
###### #  #
#
# each of the below lines loads additional code from other files... this is so this main file doesn't grow to a massive oversized
# pile of spew!

. "$home_dir/pwn_recon.sh"
. "$home_dir/pwn_brute.sh"
. "$home_dir/pwn_privesc.sh"
. "$home_dir/pwn_exploit.sh"
. "$home_dir/pwn_shells.sh"
. "$home_dir/pwn_tools.sh"
. "$home_dir/shells_msfvenom.sh"

main $@
