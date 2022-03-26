require "socket"

serv = TCPServer.open(12345)

while true
  Thread.start(serv.accept) do |s|
    p s.gets
    s.close
  end
end