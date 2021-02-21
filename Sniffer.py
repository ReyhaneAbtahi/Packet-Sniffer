import socket
from struct import*
import struct
import sys
import binascii
import textwrap
import time

# Ethernet
class ethernet:
	def __init__(self, raw_date):
		dest, src, prototype = unpack('! 6s 6s H', raw_data[:14])
		self.dest_mac = self.get_mac_addr(dest)
		self.src_mac = self.get_mac_addr(src)
		self.proto = socket.htons(prototype)
		self.data = raw_data[14:]


	def get_mac_addr(self, bytes_addr):
		bytes_str = map('{:02x}'.format, bytes_addr)
		mac_addr = ':'.join(bytes_str).upper()
		return mac_addr


#IPv4
class ip:
	def __init__(self, data):
		maindata = data
		data = unpack('!BBHHHBBH4s4s', data[:20])
		self.version = data[0] >> 4
		self.head_len = (data[0] & 0xF)*4
		self.type_of_service = data[1]
		self.length = data[2]
		self.identifier = data[3]
		self.flgs = data[4] >> 13
		self.frag_offset = data[4] & 0x1FFF
		self.ttl = data[5]
		self.proto = data[6]
		self.checksum = hex(data[7])
		self.src_ip = socket.inet_ntoa(data[8])
		self.dest_ip =socket.inet_ntoa(data[9])
		self.data = maindata[((data[0] & 0xF) * 4):]
	


#ARP
class arp:
	def __init__(self, data):
		maindata = data
		data = unpack('2s2s1s1s2s6s4s6s4s', data[:28])
		self.hardware_type = binascii.hexlify(data[0]).decode('utf-8')
		self.protocol_type = binascii.hexlify(data[1]).decode('utf-8')
		self.hardware_size = binascii.hexlify(data[2]).decode('utf-8')
		self.protocol_size = binascii.hexlify(data[3]).decode('utf-8')
		self.opcode = binascii.hexlify(data[4]).decode('utf-8')
		self.src_mac = self.get_mac_addr(data[5])
		self.src_ip = socket.inet_ntoa(data[6])
		self.dest_mac = self.get_mac_addr(data[7])
		self.dest_ip = socket.inet_ntoa(data[8])

	def get_mac_addr(self, bytes_addr):
		bytes_str = map('{:02x}'.format, bytes_addr)
		mac_addr = ':'.join(bytes_str).upper()
		return mac_addr


#ICMP
class icmp:
	def __init__(self, data):
		icmp_type, code, checksum = unpack('!BBH', data[:4])
		self.type = icmp_type
		self.code = code
		self.checksum = hex(checksum)
		self.data = repr(data[4:])


#TCP
class tcp:
	def __init__(self, data):
		maindata = data
		data = unpack('!HHLLHHHH', data[:20])
		self.src_port = data[0]
		self.dest_port = data[1]
		self.seq_num = data[2]
		self.ack_num = data[3]
		self.offset = (data[4] >> 12) * 4
		self.reserved = data[4] & 0xF
		self.tcp_flgs(data[4] & 0b111111111)
		self.win_size = data[5]
		self.checksum = hex(data[6])
		self.urg_ptr = data[7]
		self.data = maindata[self.offset:]

	def tcp_flgs(self, flag_bits):
		self.NS = (flag_bits & 0b100000000) >> 8
		self.CWR = (flag_bits & 0b010000000) >> 7
		self.ECE = (flag_bits & 0b001000000) >> 6
		self.URG = (flag_bits & 0b000100000) >> 5
		self.ACK = (flag_bits & 0b000010000) >> 4
		self.PSH = (flag_bits & 0b000001000) >> 3
		self.RST = (flag_bits & 0b000000100) >> 2
		self.SYN = (flag_bits & 0b000000010) >> 1
		self.FIN = flag_bits & 0b100000001


#UDP
class udp:
	def __init__(self, data):
		maindata = data
		data = unpack('!HHHH', data[:8])
		self.src_port = data[0]
		self.dest_port = data[1]
		self.length = data[2]
		self.checksum = hex(data[3])
		self.data = maindata[8:]


#HTTP
class http:
	def __init__(self, data):
		try:
			self.data = data.decode('utf-8')
		except:
			self.data = data


#DNS
class dns:
	def __init__(self, data):
		maindata = data
		data = unpack('!HHHHHH', data[:12])
		self.transaction_id = data[0]
		self.dns_flgs(data[1])
		self.num_queries = data[2]
		self.num_answer = data[3]
		self.num_authority = data[4]
		self.num_additional = data[5]
		self.data = maindata[12:]

	def dns_flgs(self, flag_bits):
		self.QR = (flag_bits & 0x8000) >> 15
		self.OP = (flag_bits & 0x7800) >> 11
		self.AA = (flag_bits & 0x0400) >> 10
		self.TC = (flag_bits & 0x0200) >> 9
		self.RD = (flag_bits & 0x0100) >> 8
		self.RA = (flag_bits & 0x0080) >> 7
		self.Z = (flag_bits & 0x0070) >> 4
		self.RCODE = flag_bits & 0x000F
		

#Pcap
class Pcap:
	def __init__(self, filename, link_type=1):
		self.pcap_file = open(filename, 'wb')
		self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

	def write(self, data):
		ts_sec, ts_usec = map(int, str(time.time()).split('.'))
		length = len(data)
		self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
		self.pcap_file.write(data)

	def close(self):
		self.pcap_file.close()


# Format Output Line
def format_output_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
		if size % 2:
			size-= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


#Main

pcap = Pcap('Capture.pcap')

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while(True):
	raw_data, addr = conn.recvfrom(65535)
	pcap.write(raw_data)

#Ethernet
	ether_header = ethernet(raw_data)
	print('\nEtheret Fram:')
	print('\t - Destination: {}, Source: {}, Protocol: {}'.format(ether_header.dest_mac, ether_header.src_mac,ether_header.proto))

	#IPv4
	if ether_header.proto == 8:
		ip_header = ip(ether_header.data)
		print( '\t - IPv4 Packet:') 
		print('\t\t - Version: {}, Header Length: {}, Type of service: {}, Total Length: {}, Identification: {}, IP Flags: {}, Fragment Offset: {}, Time to live: {}, Protocol: {}, Header Checksum: {}, Source Address: {}, Destination Address: {}'.format(ip_header.version, ip_header.head_len, ip_header.type_of_service, ip_header.length, ip_header.identifier, ip_header.flgs, ip_header.frag_offset, ip_header.ttl, ip_header.proto, ip_header.checksum, ip_header.src_ip, ip_header.dest_ip))

		#ICMP
		if ip_header.proto == 1:
			icmp_header = icmp(ip_header.data)
			print('\t - ICMP Packet:')
			print('\t\t - Type: {}, Code: {}, Checksum: {}'.format(icmp_header.type, icmp_header.code, icmp_header.checksum))
			print('\t\t - ICMP Data:')
			print(format_output_line('\t\t\t', icmp_header.data))

		#TCP
		elif ip_header.proto == 6:
			tcp_header = tcp(ip_header.data)
			print('\t - TCP Segment:')
			print('\t\t - Source Port: {}, Destination Port: {}'.format(tcp_header.src_port, tcp_header.dest_port))
			print('\t\t - Sequence: {}, Acknowledgment: {}'.format(tcp_header.seq_num, tcp_header.ack_num))
			print('\t\t - Offset: {}, Reserved: {}'.format(tcp_header.offset, tcp_header.reserved))
			print('\t\t - Flags:')
			print('\t\t\t - NS: {}, CWR: {}, ECE: {}'.format(tcp_header.NS, tcp_header.CWR, tcp_header.ECE))
			print('\t\t\t - URG: {}, ACK: {}, PSH: {}'.format(tcp_header.URG, tcp_header.ACK, tcp_header.PSH))
			print('\t\t\t - RST: {}, SYN: {}, FIN: {}'.format(tcp_header.RST, tcp_header.SYN, tcp_header.FIN))
			print('\t\t - Windows Size: {}, Checksum: {}, Urgent Pointer: {}'.format(tcp_header.win_size, tcp_header.checksum, tcp_header.urg_ptr))

			#HTTP
			if len(tcp_header.data) > 0 and (tcp_header.src_port == 80 or tcp_header.dest_port == 80):
				print('\t\t - HTTP Data:')
				try:
					http_header = http(tcp_header.data)
					http_info = str(http_header.data).split('\n')
					for line in http_info:
						print('\t\t\t' + str(line))

				except:
					print(format_output_line('\t\t\t', tcp_header.data))

			#DNS
			elif len(tcp_header.data) > 0 and (tcp_header.src_port == 53 or tcp_header.dest_port == 53):
				dns_header = dns(tcp_header.data)
				print('\t\t - DNS Header:')
				print('\t\t\t - Transaction ID: {}'.format(dns_header.transaction_id))
				print('\t\t\t - Flags:')
				print('\t\t\t\t - QR: {}, OP: {}, AA: {}'.format(dns_header.QR, dns_header.OP, dns_header.AA))
				print('\t\t\t\t - TC: {}, RD: {}, RA: {}'.format(dns_header.TC, dns_header.RD, dns_header.RA))
				print('\t\t\t\t - Z: {}, RCODE: {}'.format(dns_header.Z, dns_header.RCODE))
				print('\t\t\t - Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(dns_header.num_queries, dns_header.num_answer, dns_header.num_authority, dns_header.num_additional))
				print('\t\t\t - DNS Data:')
				print(format_output_line('\t\t\t\t', dns_header.data))


			elif len(tcp_header.data) > 0:
				print('\t\t - TCP Data:')
				print(format_output_line('\t\t\t', tcp_header.data))
		#UDP
		elif ip_header.proto == 17:
			udp_header = udp(ip_header.data)
			print('\t - UDP Segment:')
			print('\t\t - Source Port: {}, Destination Port: {}, Length: {}, Checksum: {}'.format(udp_header.src_port, udp_header.dest_port, udp_header.length, udp_header.checksum))

			#DNS
			if len(udp_header.data) > 0 and (udp_header.src_port == 53 or udp_header.dest_port == 53):
				dns_header = dns(udp_header.data)
				print('\t\t - DNS:')
				print('\t\t\t - Transaction ID: {}'.format(dns_header.transaction_id))
				print('\t\t\t - Flags:')
				print('\t\t\t\t - QR: {}, OP: {}, AA: {}'.format(dns_header.QR, dns_header.OP, dns_header.AA))
				print('\t\t\t\t - TC: {}, RD: {}, RA: {}'.format(dns_header.TC, dns_header.RD, dns_header.RA))
				print('\t\t\t\t - Z: {}, RCODE: {}'.format(dns_header.Z, dns_header.RCODE))
				print('\t\t\t - Questions: {}, Answer RRs: {}, Authority RRs: {}, Additional RRs: {}'.format(dns_header.num_queries, dns_header.num_answer, dns_header.num_authority, dns_header.num_additional))
				print('\t\t\t - DNS Data:')
				print(format_output_line('\t\t\t\t', dns_header.data))

			elif len(udp_header.data) > 0:
				print('\t\t - UDP Data:')
				print(format_output_line('\t\t\t', udp_header.data))
		
	#ARP
	elif ether_header.proto == 1544:
		arp_header = arp(ether_header.data)
		print('\t - ARP Packet:')
		print('\t\t - Hardware type: {}, Protocol type: {}, Hardware size: {}, Protocol size: {}, Opcode: {}, Sender MAC address: {}, Sender IP address: {}, Target MAC address: {}, Target IP address: {}'.format(arp_header.hardware_type, arp_header.protocol_type, arp_header.hardware_size, arp_header.protocol_size, arp_header.opcode, arp_header.src_mac, arp_header.src_ip, arp_header.dest_mac, arp_header.dest_ip))
		
	else:
		print('Ethernet Data:')
		print(format_output_line('\t', ether_header.data))


pcap.close()




