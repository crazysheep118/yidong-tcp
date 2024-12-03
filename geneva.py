#!/usr/bin/env python3
# iptables: iptables -t mangle -A OUTPUT -p tcp --sport 80 -m tcp --tcp-flags SYN,ACK,ACK SYN,ACK -j NFQUEUE --queue-num 100

import os
import signal
from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import sys
import threading
import traceback
import time


window_size = 17
edit_times = {}
window_scale = 7
confusion_times = 7
split_number = 7


def cleanup_edit_times(edit_times):
    while True:
        current_time = time.time()
        keys_to_delete = [] 
        
        for key, value in list(edit_times.items()):
            created_time = value[0]
            if current_time - created_time >= 10:
                try:
                    del edit_times[key]
                except:
                    pass
        time.sleep(10) 


def clear_window_scale(ip_layer):
    if ip_layer.haslayer(TCP):
        tcp_layer = ip_layer[TCP]
        tcp_options = tcp_layer.options
        new_options = []
        for i in range(len(tcp_options)):
            if tcp_options[i][0] == 'WScale':
                continue
            new_options.append(tcp_options[i])
        tcp_layer.options = new_options
    return ip_layer


def modify_window(pkt):
    global edit_times
    try:
        ip = IP(pkt.get_payload())
        if ip.haslayer(TCP):
            key = f"{ip.dst}_{ip[TCP].dport}"

            if ip[TCP].flags == "SA":
                edit_times[key] = [time.time(), 1]
                ip = clear_window_scale(ip)
                ip[TCP].window = window_size
                del ip[IP].chksum
                del ip[TCP].chksum
                pkt.set_payload(bytes(ip))

                thread = threading.Thread(target=send_payloads, args=(ip, ))
                thread.start()
            elif ip[TCP].flags == "A":
                if not key in edit_times:
                    edit_times[key] = [time.time(), 1]
                if edit_times[key][1] < split_number:
                    ip[TCP].window = window_size
                else:
                    ip[TCP].window = 28960
                edit_times[key][1] += 1
                del ip[IP].chksum
                del ip[TCP].chksum
                pkt.set_payload(bytes(ip))
    except Exception as e:
        # print(traceback.format_exc())
        pass
    pkt.accept()



def send_payloads(ip):
    if confusion_times < 1:
        return 
    for i in range(1,confusion_times+1):
        _win_size = window_size
        if i == confusion_times:
            _win_size = 65535
        ack_packet = IP(src=ip.dst, dst=ip.src) / TCP(sport=ip[TCP].dport, dport=ip[TCP].sport, flags="A", ack=ip[TCP].seq +i, window=_win_size, options=[('WScale', window_scale)] + [('NOP', '')] * 5)
        send(ack_packet, verbose=False)

def parsearg():
    global window_size
    global window_scale
    global confusion_times
    global split_number
    parser = argparse.ArgumentParser(description='Description of your program')

    parser.add_argument('-q', '--queue', type=int, help='iptables Queue Num')
    parser.add_argument('-w', '--window_size', type=int, help='Tcp Window Size')
    parser.add_argument('-s', '--window_scale', type=int, help='Tcp Window Scale')
    parser.add_argument('-c', '--confusion_times', type=int, help='confusion_times')
    parser.add_argument('-n', '--split_number', type=int, help='Tcp Split Number')


    args = parser.parse_args()

    if args.queue is None or args.window_size is None:
        exit(1)

    window_size = args.window_size
    window_scale = args.window_scale
    confusion_times = args.confusion_times
    split_number = args.split_number

    return args.queue

def main():
    thread = threading.Thread(target=cleanup_edit_times, args=(edit_times, ))
    thread.start()
    queue_num = parsearg()
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, modify_window)

    try:
        print("Starting netfilter_queue process...")
        nfqueue.run()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda signal, frame: sys.exit(0))
    main()
