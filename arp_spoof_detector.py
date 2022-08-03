import smtplib
import time
from datetime import datetime, date
import psutil
import scapy.all as scapy
import socket


class InterfaceNotFound(Exception):
    pass


def failure(exception):
    send_mail("<YOUR_EMAIL>", "<YOUR_PASSWORD>", "\nprogram failed to run\n" + str(exception))


try:

    interface = "Wi-Fi"
    time_gap = 5 * 60

    def start():
        if check_interface(interface):
            sniff(interface)
        else:
            raise InterfaceNotFound


    def check_interface(interface):
        interface_add = psutil.net_if_addrs().get(interface) or []
        return socket.AF_INET in [snicaddr.family for snicaddr in interface_add]


    def sniff(iface):
        scapy.sniff(iface=iface, store=False, prn=modifying_packet)


    def modifying_packet(packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            sus_MAC = packet[scapy.ARP].hwsrc
            real_MAC = get_mac(packet[scapy.ARP].psrc)
            if (real_MAC is not None) and (real_MAC != sus_MAC):
                packet.show()
                code_red(packet, sus_MAC)


    def code_red(packet, sus_MAC):
        now = datetime.now()
        current_date = str(date.today())
        current_time = now.strftime("%H:%M:%S")
        today = current_date + " at " + current_time
        file_to_write = open(r"C:\Users\Al8m_\Desktop\codeRed_Wifi.txt", "a")
        file_to_write.write("--------------------------------------------------------------------\n"
                            "" + str(today) + "\npossible arp spoofing attack, attacker MAC address " + str(sus_MAC) +
                            "\n" + str(
            packet.summary()) + "\n--------------------------------------------------------------------\n\n")
        file_to_write.close()
        send_mail("<YOUR_EMAIL>", "<YOUR_PASSWORD>", "\npossible arp spoofing attack \n" + str(sus_MAC))
        print("possible arp spoofing attack")
        time.sleep(time_gap)
        start()


    def send_mail(address, password, msg):
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(address, password)
        server.sendmail(address, address, msg)
        server.quit()


    def get_mac(ip):
        arp_req = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast / arp_req
        results = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
        try:
            return results[0][1].hwsrc
        except IndexError:
            pass


except InterfaceNotFound:
    failure(InterfaceNotFound)
except Exception:
    failure(Exception)
