#Written by Avi Feder && Daniel Yohanan
import hashlib
import sys
import threading
import multiprocessing
from time import sleep
import libnum
import socket
from cryptography.fernet import Fernet
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.config import conf
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw
from scapy.sendrecv import sniff, sendp, srp


# length of key exchange massage
LENGTH_FIELD_SIZE = 1024

# massage to ask for key exchange
HELLO_MASSEGE = "get_key"

# port to connect to key exchange server
KEY_EXCHANGE_PORT = 23459

# port to send the hash packets
CLIENT_PORT = 2346

# RD Gateway Server IP address
GW_IP = "192.168.68.115"

# RD Server IP address
RD_IP = "147.161.1.113"

# interface for use
IFACE = conf.iface

# client IP address
MY_IP = get_if_addr(IFACE)

# client MAC address
MY_MAC = get_if_hwaddr(IFACE)

# interface name
IFACE = IFACE.data["name"]

# defaulte gateway IP address
DEFAULT_GW_IP = conf.route.route("0.0.0.0")[2]

# dictionary to coordination between ports and symmetric keys
key_dict = {}

# time in seconds to re-exchange keys
RENEW_KEY = 60

# mutex to locking the dictionary Encryption keys.
# that locked each time we access the dictionary,
# to prevent data overload or use of outdated keys.
mutex = threading.Lock()

# the parameters of the asymmetric key
p = 66961118513594530905681397121276860461949739015330618227110767856262544636978765411607972854520393470039554569810723812259605832300525942258500090234068762976534950761363578541057743111011009631864640833532201998451033270143722483633609144416056852752202272257328128113563953564132143786064863269745135651741
q = 70905510723315780404364929340203746922072378664341864675958659885543889445347107247916217494296660369686908698163653376442610954107342501569481608437735396332774083633430454161158092610038164986656259012420279829993596849143948127629266088204223472414385673606949628003481900489614890026362254591274979911007
n = p * q
PHI = (p - 1) * (q - 1)
e = 65537
d = libnum.invmod(e, PHI)


def get_mac(ip):
    """
    This function performs ARP querying to find a MAC address for IP.
    :param ip: The IP address
    :return: The MAC address
    """
    p = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
    result = srp(p, verbose=False, iface=IFACE)[0]
    return result[0][1].hwsrc if result else None


VM_MAC = get_mac(GW_IP)
DEFAULT_GW_MAC = get_mac(DEFAULT_GW_IP)


def create_msg(data):
    """
    Create a valid protocol message, with length field
    :return: message to send.
    """
    length = str(len(str(data))).zfill(LENGTH_FIELD_SIZE)
    return length + data


def get_msg(my_socket):
    """
    Extract message from protocol, without the length field
    :return: If length field does not include a number, returns False, "Error".
            else, return the message.
    """
    length = my_socket.recv(LENGTH_FIELD_SIZE).decode()
    if str(length).isdigit():
        message = my_socket.recv(int(length)).decode()
        return True, message
    else:
        return False, 'ERROR'


def get_key(data):
    """
    This function receives the symmetric key encrypted by asymmetric encryption,
    and decrypts the encryption.
    :param data: The symmetric key encrypted by asymmetric encryption.
    :return: decrypt symmetric key.
    """
    decrypt_key = pow(int(data), d, n)
    return decrypt_key


def keyExchangeClient(port):
    """
    This function uses sockets to connect the  RD Gateway Server
    and get a symmetric encryption key from it.
    The symmetric key is receive encrypted by asymmetric encryption.
    :param port: The port to connect to the server.
    :return:
    """
    try:
        with socket.socket() as sock:
            sock.connect((GW_IP, KEY_EXCHANGE_PORT))
            sock.send(create_msg(HELLO_MASSEGE + " " + str(port)).encode())
            valid, data = get_msg(sock)
            if valid:
                key = get_key(data)
                key_dict[port] = key
            print(key_dict)
    except Exception as e:
        print(e, "error in keyExchangeClient")


def sendHash(p):
    """
    This function receives packets from the sniff function.
    This function performs the hash on the tcp layer including the data,
    encrypts the hash by a symmetric key and sends the packets
    to the RD Gateway Server.
    :param p:  packets from the sniff function
    """
    try:
        if IP in p and p[IP].dst == RD_IP and p[IP].src == MY_IP and TCP in p and p[Ether].src == MY_MAC:
            if p[TCP].sport not in key_dict.keys():
                mutex.acquire()
                if p[TCP].sport not in key_dict.keys():
                    keyExchangeClient(p[TCP].sport)
                if mutex.locked():
                    mutex.release()
            f = Fernet(key_dict[p[TCP].sport].to_bytes(64, byteorder="big"))
            hash = str(hashlib.sha256(bytes(p[TCP])).hexdigest())
            encrypted_message = f.encrypt(hash.encode())
            pToSend = Ether(dst=DEFAULT_GW_MAC) / IP(version=4, src=MY_IP, dst=GW_IP)\
                      / UDP(sport=p[TCP].sport, dport=CLIENT_PORT) / Raw(load=encrypted_message)
            pToSend.show2()
            sleep(0.2)
            sendp(pToSend, iface=IFACE, verbose=0)
    except Exception as e:
        print(e, "error in sendHash")
    finally:
        if mutex.locked():
            mutex.release()
        sys.exit()


def renewKey():
    """
    This function is responsible for an encryption key exchange
    according to the time set for it.
    """
    while True:
        try:
            sleep(RENEW_KEY)
            mutex.acquire()
            key_dict.clear()
            mutex.release()
        except:
            print("error in renew key")
        finally:
            if mutex.locked():
                mutex.release()


def sniffing():
    """
    This is the main function that sniff packets
    and transfers them to the hash function
    """
    sniff(store=False, prn=lambda p: threading.Thread(target=sendHash, args=(p,)).start(), iface=IFACE)


def main():
    multiprocessing.Process(target=sniffing, ).start()
    multiprocessing.Process(target=renewKey, ).start()


if __name__ == '__main__':
    main()
