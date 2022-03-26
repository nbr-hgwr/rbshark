require "socket"
require 'readline'

ip_addr = ARGV[0] if ARGV.size == 1

while true
  s = TCPSocket.open(ip_addr, 12345)

  line = Readline.readline('> ')
  s.write(line)
  s.close
end