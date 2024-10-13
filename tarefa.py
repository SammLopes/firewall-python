import tkinter as tk
from tkinter import messagebox
from scapy.all import IP, TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
from scapy.all import sniff
from datetime import datetime

regras_firewall = {
    'allow': [],
    'block': [{'ip_org': '192.168.0.1', 'ip_dst': 22}],
    'trainer_group':['192.168.0.10', '192.168.0.11']
}

pacotes_interceptados = []

def verificarPacote(packet):

    print(packet);
    if regra_permitir_http(packet):
        print("Pacote HTTP permitido")
        
        # Verificar se é um conteúdo de vídeo bloqueado
        if verificar_conteudo_video(packet):
            print("Conteúdo de vídeo permitido")
          
            return True  # Se não for bloqueado, o pacote é permitido

        print("Conteúdo de vídeo bloqueado")
        return False  # Se for vídeo bloqueado, retorna False
    else:
        print("Pacote não permitido")
        return False  # Se não for HTTP, retorna False

def regra_permitir_http(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if dst_port == 80:

            pacotes_interceptados.append(f"Pacote permitido: {src_ip} para porta {dst_port}")
            print('Lista de pacotes bloqueados ',pacotes_interceptados ,' \n');
            return True
        else:
            pacotes_interceptados.append(f"Bloqueado pacote {src_ip} para porta {dst_port}")
            print(f"Bloqueado pacote {src_ip} para porta {dst_port} \n")
            return False
    else:
        print("Pacote não é IP/TCP")
        pacotes_interceptados.append(f"Pacote não processado: {packet.summary()}")
        return False

def verificar_conteudo_video(packet):
    if packet.haslayer(HTTPResponse):
        http_layer = packet[HTTPResponse]
        content_type = http_layer.getfieldval('Content_Type')
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if isinstance(content_type, bytes):
            print('Teste content')
            content_type = content_type.decode('utf-8')

        if content_type and any(video_type in content_type.lower() for video_type in ['video/mp4', 'video/webm', 'video/ogg', 'video/mpeg']):
            
            if is_trainer(src_ip):      

                if is_night_time():
                    print('------- Pacote a noite -------')
                    pacotes_interceptados.append(f"Bloqueado pacote de vídeo para Trainer à noite: {src_ip} para porta {dst_port}")
                    print(f"Bloqueado pacote de vídeo para Trainer à noite: {src_ip} para porta {dst_port}")
                    return False
                else:
                    pacotes_interceptados.append(f"Pacote de vídeo permitido para Trainer: {src_ip} para porta {dst_port}")
                    print(f"Pacote de vídeo permitido para Trainer: {src_ip} para porta {dst_port}")
                    return True
            pacotes_interceptados.append(f"Bloqueado conteúdo de vídeo: {src_ip} para porta {dst_port}")
            print(f"Bloqueado conteúdo de vídeo: {src_ip} para porta {dst_port} \n")
            return False

        return True
          

def is_trainer(src_ip):
    return src_ip in regras_firewall['trainer_group']

def is_night_time():
    current_hour = datetime.now().hour
    return current_hour >= 22 or current_hour < 6