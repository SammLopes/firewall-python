'''
Scapy é uma ferramenta de manipulação de pacotes para redes de computadores , [3] [4] escrita em Python por Philippe Biondi. Ele pode forjar ou decodificar pacotes , enviá-los na rede, capturá-los e corresponder a solicitações e respostas. Ele também pode manipular tarefas como varredura, tracerouting , sondagem, testes de unidade , ataques e descoberta de rede .
O Scapy fornece uma interface Python para a libpcap , (WinPCap / Npcap no Windows), de maneira similar àquela em que o Wireshark fornece uma visão e captura da GUI . Ele pode interagir com uma série de outros programas para fornecer visualização incluindo Wireshark para pacotes de decodificação, gnuplot para fornecer gráficos, graphviz ou VPython para visualização, etc.
O Scapy suporta o Python 3 desde 2018 (scapy 2.4.0+). Kamene é um fork independente de scapy originalmente chamado scapy3k.
https://pt.wikipedia.org/wiki/Scapy

https://www.ethicalhacker.com.br/site/2013/02/scapy/
'''

import tkinter as tk
from tkinter import messagebox
from scapy.all import IP, TCP
import threading
from scapy.all import sniff

regras_firewall = {
    'allow': [],
    'block': [{'ip_org': '192.168.0.1', 'ip_dst': 22}]
}

pacotes_bloqueados = []

def verificarPacote(packet):
    print(packet)
    if packet.haslayer(IP) and packet.haslayer(TCP):
        for rule in regras_firewall['block']:
            if packet[IP].src == rule['ip_org'] and packet[TCP].dport == rule['ip_dst']:
                pacotes_bloqueados.append(f'Bloqueado pacote {packet[IP].src} para porta {packet[TCP].dport}')
                atualizarListagem()
                return False
    pacotes_bloqueados.append(f'Pacote permitido pelo {packet[IP].src} para porta {packet[TCP].dport}')
    atualizarListagem()
    return False

def iniciarFirewall():
    try:
        print("---------RODANDO FIREWALL------------")
        while True:
            print("Verificando pacotes na rede....")
            sniff(filter="ip", prn=verificarPacote, store=0)
    except Exception as e:
        print(f"ERRO: {e} || Execute como admin!")

def adicionarRegraBloqueio():
    if blkip_entrada.get() and blkip_porta.get():
        regras_firewall['block'].append({'ip_org': blkip_entrada.get(), 'ip_dst': int(blkip_porta.get())})
        update_regras_firewall_list()
    else:
        messagebox.showwarning("ERRO", "Insira IP e porta!")

def atualizarListagem():
    lb_bloqueios.delete(0, tk.END)
    for packet in pacotes_bloqueados:
        lb_bloqueios.insert(tk.END, packet)

def update_regras_firewall_list():
    listbox_regras_firewall.delete(0, tk.END)
    for rule in regras_firewall['block']:
        listbox_regras_firewall.insert(tk.END, f"Bloqueio: IP {rule['ip_org']} Porta {rule['ip_dst']}")

def enviarPacote():
    print(ip_ent_org.get())
    if ip_ent_org.get() and ip_ent_dst.get():
        packet = IP(src=ip_ent_org.get()) / TCP(dport=int(ip_ent_dst.get()))
        verificarPacote(packet)
    else:
        messagebox.showwarning("ERRO", "Insira IP e porta")

def criarGui():
    global blkip_entrada, blkip_porta, lb_bloqueios, listbox_regras_firewall, ip_ent_org, ip_ent_dst
    
    window = tk.Tk()
    window.title("Simulador de Firewall")

    frame_regras_firewall = tk.Frame(window)
    frame_regras_firewall.pack(pady=10)
    # Label e input para entrada para bloquio de Ip
    tk.Label(frame_regras_firewall, text="Bloqueio IP:").grid(row=0, column=0)
    blkip_entrada = tk.Entry(frame_regras_firewall)
    blkip_entrada.grid(row=0, column=1)
    # Label e input para entrada para bloquio de porta
    tk.Label(frame_regras_firewall, text="Bloqueio Porta:").grid(row=1, column=0)
    blkip_porta = tk.Entry(frame_regras_firewall)
    blkip_porta.grid(row=1, column=1)
    # Botão Add Bloqueio
    btn_add_rega = tk.Button(frame_regras_firewall, text="Add Bloqueio", command=adicionarRegraBloqueio)
    btn_add_rega.grid(row=2, columnspan=2, pady=5)
    #Lista com as regras do firewall 
    listbox_regras_firewall = tk.Listbox(window, width=50)
    listbox_regras_firewall.pack(pady=10)
    update_regras_firewall_list()
    # Lista pacotes bloqueados
    tk.Label(window, text="PACOTES BLOQUEADOS:").pack()
    lb_bloqueios = tk.Listbox(window, width=50, height=10)
    lb_bloqueios.pack(pady=10)
    #Frame de pacotes 
    frame_simulador = tk.Frame(window)
    frame_simulador.pack(pady=10)
    # Label ip origem 
    tk.Label(frame_simulador, text="IP origem:").grid(row=0, column=0)
    ip_ent_org = tk.Entry(frame_simulador)
    ip_ent_org.grid(row=0, column=1)
    #Frame porta destino 
    tk.Label(frame_simulador, text="Porta destino:").grid(row=1, column=0)
    ip_ent_dst = tk.Entry(frame_simulador)
    ip_ent_dst.grid(row=1, column=1)
    #btn envio de pacote 
    btn_env_pacote = tk.Button(frame_simulador, text="Enviar pacote", command=enviarPacote)
    btn_env_pacote.grid(row=2, columnspan=2, pady=5)
    
    window.mainloop()

def main():
    firewall_thread = threading.Thread(target=iniciarFirewall, daemon=True)
    firewall_thread.start()
    criarGui()

if __name__ == '__main__':
    main()