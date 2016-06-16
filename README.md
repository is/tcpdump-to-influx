##

on gateway:

  tcpdump -i br0 -tt -pqn not port 1212 | nc receiver 1212

