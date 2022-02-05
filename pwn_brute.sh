#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - brute
################### #### ## #  #    #
#
# >> this file contains the "brute" sub menu and all it's functions

menu_brute()
{
    menu="$(pfx -n "JOHN") JohnTheRipper - hash cracking\n<small>crack those hashes</small>$lb$(pfx -n "HASHCAT") HashCat - hash cracking\n<small>yet another hash cracker</small>$lb$(pfx -n "HYDRA") Hydra - brute-force logins\n<small>brute-force your way in via many popular protocols</small>$lb$lbrk$lb$(pfx -n "BACK") go back..."
	msg="pwnMENU > <b>brute</b>\n<small>crack found hashes or brute-force your way in to the target!</small>"
	result=$(echo -e "$menu" | rf "BRUTE" "$msg" 5)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"JOHN")
			brute_john
			;;
		"HASHCAT")
			brute_hashcat
			;;
		"HYDRA")
			brute_hydra
			;;
		"BACK")
			main
			;;
	esac
}

brute_john()
{
    rf_msg "$(pfx "INFO") coming soon... watch this space!"
}

brute_hashcat()
{
    rf_msg "$(pfx "INFO") coming soon... watch this space!"
}

brute_hydra()
{
    rf_msg "$(pfx "INFO") coming soon... watch this space!"
}
