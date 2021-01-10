from datetime import datetime
import hashlib
import sys
import threading
from time import sleep
from scapy.arch import get_if_addr, get_if_hwaddr
from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, send
from cryptography.fernet import Fernet
import socket

# the parameters of the asymmetric key
e = 65537
n = 4747912306810895841487898042464375273401481768881765927995488043892570034479065132765231426482318285927736088291591967602696211819018920591922249540535939083241807798495115683397862558599302412888224379482521765270284061472147221468249967095055417393841113179874616884274533321107525727675694837630592891791503418914095057299855043645258481901354724472520712837231429287916284257508234796852491409964167014141083545160885043972137908545769883218260474750164204672171367261800861417279039106921517112057088964412377477192195775736028770950434350269936592037849195914413784050630608984354241373671094830017883124613187
# length of key exchange massage
LENGTH_FIELD_SIZE = 1024
# massage to ask for key exchange
HELLO_MASSEGE = "get_key"
# port to connect to key exchange server
KEY_EXCHANGE_PORT = 23458
# port to send the hash packets
CLIENT_PORT = 2346
# A dictionary that keeps the symmetric keys in close proximity to the IP address and port.
key_dic = {}
# A dictionary that keeps the fire of packages sent by the client.
checkIP_dict = {}
# A dictionary that saves the blocked IP address and the time it was blocked.
black_list = {}
# A dictionary that keeps counter of the remove of hash made to each client
remove_counter = {}
# mutex to locking the dictionary Encryption keys.
# that locked each time we access the dictionary,
# to prevent data overload or use of outdated keys.
mutex = threading.Lock()
# mutex to locking the blacklist dictionary.
# that locked each time we access the dictionary,
# to prevent data overload or use of outdated keys.
black_list_mutex = threading.Lock()
# RD Server IP address
RD_ADRRESS = "147.161.1.113"
# interface for use
IFACE = conf.iface
# RD Gateway Server IP address
GW_ADRRESS = get_if_addr(IFACE)
# RD Gateway Server MAC address
GW_MAC_ADRRESS = get_if_hwaddr(IFACE)
# interface name
IFACE = IFACE.data["name"]
# Time to check whether to release a blocked client
FREE_BLACK_LIST = 10
# Time to release a blocked client
SECONDS_TO_FREE = 60 * 60
# Maximum packages that do not require approval.
PACKETS_TO_BLOCK = 60
# Appointed to reset the quantity of packages without approval.
REMOVE_COUNTER = 15


def get_key(key):
    """
    This function encrypts the symmetric key by asymmetric encryption.
    :param key: Symmetric key
    :return: Symmetrical key is encrypted with an asymmetric key
    """
    encrypt_key = pow(key, e, n)
    return encrypt_key


def create_msg(data):
    """
    Create a valid protocol message, with length field
    :return: message to send.
    """
    length = str(len(str(data))).zfill(LENGTH_FIELD_SIZE)
    return length + str(data)


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


def keyExchangeServer():
    """
    This function is responsible for exchanging keys with the clients.
    it opens a socket and waits for client to try to connect.
    After a client connect in, it assigns the client a symmetric encryption key according to the Mac and IP address.
    And passes it to the client, encrypted by asymmetric encryption.
    """
    with socket.socket() as sock:
        try:
            # if the port number already taken, the following line will not work
            sock.bind((GW_ADRRESS, KEY_EXCHANGE_PORT))
            print("success in binding")
        except:
            print("error in binding")
            sys.exit()
        sock.listen(0)
        while True:
            client_socket, client_address = sock.accept()
            valid, data = get_msg(client_socket)
            if valid:
                data = data.split(" ")
                if data[0] == HELLO_MASSEGE:
                    if (client_address[0], int(data[1])) not in key_dic:
                        key = int.from_bytes(Fernet.generate_key(), "big")
                    else:
                        key = key_dic[(client_address[0], int(data[1]))]
                    client_socket.send(create_msg(get_key(key)).encode())
                    key_dic[(client_address[0], int(data[1]))] = key
                    print(key_dic)


def forward(p):
    """
    This function forwards the packages from the client to RD Server
    :param p: the sniffed packet.
    """
    try:
        if IP in p and p[IP].dst == RD_ADRRESS and p[Ether].src != GW_MAC_ADRRESS and p[Ether].dst == GW_MAC_ADRRESS:
            if p[IP].src not in black_list:
                send(p[1::], iface=IFACE, verbose=0)
    except:
        print("error in forward")
    finally:
        sys.exit()


def next(p):
    """
    This function receives the sniffed packets,
    and transfers them to actual handling in a number of different functions, by using threading.
    :param p: the sniffed packet.
    """
    threading.Thread(target=forward, args=(p,)).start()
    threading.Thread(target=insertData, args=(p,)).start()
    threading.Thread(target=clientListen, args=(p,)).start()
    sys.exit()


def sniffing():
    """
    This function is responsible for sniff out the packages and transferring them for treatment.
    """
    sniff(store=False, prn=lambda p: threading.Thread(target=next, args=(p,)).start(), iface=IFACE)


def insertData(p):
    """
    This function takes information packets from the client,
    and executes to the required layers the hash and insert the hash to the dictionary,
    so that we can verify the client later.
    :param p: packet that come from the client.
    """
    try:
        if IP in p and p[IP].dst == RD_ADRRESS and p[Ether].src != GW_MAC_ADRRESS and p[
            Ether].dst == GW_MAC_ADRRESS and TCP in p:
            hash = hashlib.sha256(bytes(p[TCP])).hexdigest()
            key = (p[IP].src, p[TCP].sport)
            mutex.acquire()
            if key in checkIP_dict and hash not in checkIP_dict[key]:
                checkIP_dict[key] = checkIP_dict[key] + [hash]
            elif key not in checkIP_dict:
                checkIP_dict[key] = [hash]
            mutex.release()
            print(len(checkIP_dict[key]), key, "insert")
    except Exception as e:
        print(e, "error in insertData")
    finally:
        if mutex.locked():
            mutex.release()
        sys.exit()


def removeData(hash, key):
    """
    This function is actually responsible for removing the necessary information from the dictionary.
    :param hash: hash that come from the client
    :param key: Coupling of IP address and port - dictionary key.
    """
    try:
        mutex.acquire()
        if key in checkIP_dict and hash in checkIP_dict[key]:
            checkIP_dict[key].remove(hash)
        mutex.release()
        print(len(checkIP_dict[key]), key, "remove")
    except Exception as e:
        print(e, "error in removeData")
    finally:
        if mutex.locked():
            mutex.release()


def removeCounter(key):
    """
    This function is responsible for handling the numbering of the removed packages
    :param key: Coupling of IP address and port - dictionary key.
    """
    try:
        if key not in remove_counter:
            remove_counter[key] = 1
            return

        remove_counter[key] = remove_counter[key] + 1
        if remove_counter[key] > REMOVE_COUNTER:
            remove_counter[key] = 0
            mutex.acquire()
            checkIP_dict[key] = []
            mutex.release()
    except:
        print("error in decrypt")
    finally:
        if mutex.locked():
            mutex.release()


def clientListen(p):
    """
    This function handles the hash packages that come from the client.
    It decrypt the packages and removes the necessary information from the dictionary
    :param p: hash packages
    """
    try:
        if IP in p and p[IP].dst == GW_ADRRESS and UDP in p and p[UDP].dport == CLIENT_PORT:
            key = (p[IP].src, p[UDP].sport)
            hash = p.load
            f = Fernet(key_dic[key].to_bytes(64, byteorder="big"))
            decrypted_message = f.decrypt(hash).decode()
            removeData(decrypted_message, key)
            removeCounter(key)
    except:
        print("error in decrypt")
    finally:
        sys.exit()


def blackList():
    """
    This function is responsible for blocking the IP according to the limit of packets not approved by the hash.
    """
    try:
        while True:
            sleep(1)
            mutex.acquire()
            checkIP_dict_copy = dict(checkIP_dict)
            mutex.release()
            for ipList in checkIP_dict_copy:
                if len(checkIP_dict_copy[ipList]) > PACKETS_TO_BLOCK:
                    black_list_mutex.acquire()
                    if ipList[0] not in black_list:
                        mutex.acquire()
                        del checkIP_dict[ipList]
                        mutex.release()
                        black_list[ipList[0]] = datetime.now()
                    black_list_mutex.release()
            print(black_list)
    except Exception as e:
        print(e, "error in black list ip")
    finally:
        if mutex.locked():
            mutex.release()
        if black_list_mutex.locked():
            black_list_mutex.release()
        sys.exit()


def freeBlackList():
    """
    This function is responsible for releasing the blocked IP by the set time.
    """
    try:
        while True:
            sleep(FREE_BLACK_LIST)
            t = datetime.now()
            black_list_mutex.acquire()
            black_list_copy = dict(black_list)
            black_list_mutex.release()
            for blackIp in black_list_copy:
                if (t - black_list_copy[blackIp]).total_seconds() > SECONDS_TO_FREE:
                    black_list_mutex.acquire()
                    del black_list[blackIp]
                    black_list_mutex.release()

    except:
        print("error in free black list ip")
    finally:
        if black_list_mutex.locked():
            black_list_mutex.release()
        sys.exit()


if __name__ == '__main__':
    threading.Thread(target=keyExchangeServer, ).start()
    threading.Thread(target=sniffing, ).start()
    threading.Thread(target=blackList, ).start()
    threading.Thread(target=freeBlackList, ).start()
