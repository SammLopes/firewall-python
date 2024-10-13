import unittest
from scapy.all import IP, TCP
from scapy.layers.http import HTTPResponse
from tarefa import verificarPacote, pacotes_interceptados
from unittest import mock
from datetime import datetime

class TesteFirewall(unittest.TestCase):

    def setUp(self):
        pacotes_interceptados.clear();
    def test_permit_http(self):
        # Simula um pacote HTTP
        packet = IP(src="192.168.0.5") / TCP(dport=80) /  HTTPResponse(Content_Type="text/html")
        self.assertTrue(verificarPacote(packet))
        print('Lista de pacote no test ',pacotes_interceptados);
        self.assertIn('Pacote permitido: 192.168.0.5 para porta 80', pacotes_interceptados)
       
    def test_block_non_http(self):
        # Simula um pacote em uma porta não HTTP
        packet = IP(src="192.168.0.5") / TCP(dport=22)
        self.assertFalse(verificarPacote(packet))
        print('Lista de pacote no test ',pacotes_interceptados);
        self.assertIn('Bloqueado pacote 192.168.0.5 para porta 22', pacotes_interceptados)
       
    def test_block_video_non_trainer(self):
        # Simula um pacote de vídeo de um usuário não Trainer
        packet = IP(src="192.168.0.6") / TCP(dport=80) / HTTPResponse(Content_Type='video/mp4')
        self.assertFalse(verificarPacote(packet))
        print('Lista de pacote no test ',pacotes_interceptados);
        self.assertIn('Bloqueado conteúdo de vídeo: 192.168.0.6 para porta 80', pacotes_interceptados)

    def test_permit_video_trainer_day(self):
        # Simula um pacote de vídeo de um Trainer durante o dia
        print("Teste video trainers dia");
        packet = IP(src="192.168.0.10") / TCP(dport=80) / HTTPResponse(Content_Type='video/mp4')
        self.assertTrue(verificarPacote(packet))
        self.assertIn('Pacote de vídeo permitido para Trainer: 192.168.0.10 para porta 80', pacotes_interceptados)

    def test_block_video_trainer_night(self):
        # Simula um pacote de vídeo de um Trainer à noite
        packet = IP(src="192.168.0.10") / TCP(dport=80) / HTTPResponse(Content_Type='video/mp4')
        
        # Força a hora atual para ser 23:00 (noite)
        with mock.patch('tarefa.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 10, 12, 23, 0)
            self.assertFalse(verificarPacote(packet))
            self.assertIn('Bloqueado pacote de vídeo para Trainer à noite: 192.168.0.10 para porta 80', pacotes_interceptados)
    
if __name__ == '__main__':
    unittest.main()


