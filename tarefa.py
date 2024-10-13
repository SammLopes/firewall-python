import tkinter as tk
from tkinter import messagebox
from scapy.all import IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
from scapy.all import sniff
from datetime import datetime


regras_firewall = {
    'allow': [],
    'block': [{'ip_org': '192.168.0.1', 'ip_dst': 22}]
}

pacotes_bloqueados = []

trainers_group_ips = ['192.168.0.10', '192.168.0.11']

def verificarPacote(packet):

    print(packet);
    #VErificar o pacote se ele é TCP oi IP
    
    


def is_trainer(src_ip):
    return src_ip in trainers_group_ips

def is_night_time():
    current_hour = datetime.now().hour
    return current_hour >= 22 or current_hour < 6

def regra_permitir_http(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        # Permitir somente se a porta for 80
        if dst_port == 80:
            print(f"Pacote permitido: {src_ip} para porta {dst_port}")
            return True
        else:
            pacotes_bloqueados.append(f"Bloqueado pacote {src_ip} para porta {dst_port}")
            print(f"Bloqueado pacote {src_ip} para porta {dst_port}")
            return False
    else:
        print("Pacote não é IP/TCP")
        pacotes_bloqueados.append(f"Pacote não processado: {packet.summary()}")
        return False

   # Identificando trafego de video 
        # if content_type and any(video_type in content_type.lower() for video_type in ['video/mp4', 'video/webm', 'video/ogg', 'video/mpeg']):
        #     if is_trainer(src_ip):
        #         if is_night_time:
        #             pacotes_bloqueados.append(f'Pacote de vídeo permitido para Trainer: {src_ip}')
        #             return True
        #         else:
        #             pacotes_bloqueados.append(f'Bloqueado pacote de vídeo para Trainer à noite: {src_ip}')
        #             return False
        #     else:
        #         pacotes_bloqueados.append(f'Bloqueado pacote de vídeo: {src_ip}')
        #         return False