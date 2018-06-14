# OpenMPTCProuter VPS scripts

All scripts needed to install OpenMPTCProuter VPS.

This is the VPS part of [OpenMPTCProuter](https://www.openmptcprouter.com/), a solution to aggregate multiple internet connections.
 
* ```debian9-x86_64.sh```: The main script install ShadowSocks, Glorytun TCP, Glorytun UDP, Shorewall, the MPTCP kernel and can install OpenVPN
* ```debian9-x86_64-mlvpn.sh```: Script to install MLVPN
* ```config.json```: shadowsocks config
* ```/shorewall4```: shorewall default configuration
* ```/shorewall6```: shorewall6 default configuration
* ```glorytun-tcp-run```: script to run glorytun with configuration parameters
* ```glorytun-tcp@.service.in```: glorytun systemd service
* ```glorytun.network```: glorytun systemd network (for DHCP)
* ```glorytun-udp-run```: script to run glorytun UDP with configuration parameters
* ```glorytun-udp.network```: glorytun UDP systemd network (for DHCP)
* ```glorytun-udp@.service.in```: glorytun UDP systemd service
* ```mlvpn.network```: MLVPN systemd network (for DHCP)
* ```mlvpn0.conf```: MLVPN default config
* ```omr-6in4-service```: Script used to make 6in4 tunnel always up and detect ip used by OpenMPTCProuter to config Shorewall
* ```omr-6in4.service.in```: Systemd service to run the script
* ```openvpn-tun0.cnf```: OpenVPN default config
* ```openvpn.network```: OpenVPN systemd network (for DHCP)
* ```shadowsocks.conf```: shadowsocks sysctl.d optimization and mptcp config
* ```tun0.glorytun```: glorytun default configuration
* ```tun0.glorytun-udp```: glorytun default configuration
* ```update-grub.sh```: Script used to check if MPTCP kernel is the default

