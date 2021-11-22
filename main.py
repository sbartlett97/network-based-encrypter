import scapy.all as scapy
import argparse
import hashlib
import socket
from cryptography.fernet import Fernet

def get_args():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', '--file', dest='file', help='File to be encrypted/decrypted')
  parser.add_argument('-t', '--text', dest='text', help='String to be encryprted/decrypted (Testing purposes only)')
  parser.add_argument('-e', '--encrypt', dest='encrpyt', const=True, default=False, 
  help='Used to perform encryption on the specified data. Cannont be specified alongside -d')
  parser.add_argument('-d', '--decrypt', dest='decrypt', const=True, default=False, help='Used to perform decryption on specified data. Cannot be specified with -e')


  options = parser.parse_args()

  #Check that we have been passed either encrypt or decrypt as an option, but never both
  if (not options.decrypt and not options.encrypt) or (options.decrypt and options.encrypt):
    parser.error("[-] Please specify one of encrpyt or decrypt. Use --help for info ")

  #check data has been passed for operastion - never both
  if (not options.file and not options.text) or (options.file and options.text):
    parser.error("[-] Please specify some data for encryption or decryption. Use --help for info")

  options = parser.parse_args()


def scan(ip):
  #Using the scapy library, scan the current network domain for active hosts

  #create the arp request and broadcast frame and combine them
  arp_req = scapy.ARP(pdst=ip)
  ether_frame = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
  arp_frame = ether_frame/arp_req

  #send our arp request to the specified adress range (determined by determine_subnet function)
  answers = scapy.srp(arp_frame, 1, verbose=False)[0]

  result = ''
  #loop over the responses recieved and pull out the MAC address to build our string for hashing
  for [i, m] in answers:
    result.append(m +':')

  return result

def determine_ip_range():
  #Figure out the ip address structure and return a relevant range for the scan() function to operate on
  hostname = socket.gethostname()
  ip = socket.gethostbyname(hostname).split('.')
  return('{}.{}.{}.1/254'.format(ip[0], ip[1], ip[2]))

def perform_decryption(data, mac_string):
  return

def perform_encryption(data, mac_string):
  return

#testing with default value
if __name__=='__main__':
  text = 'Hello, World!'
  ip = determine_ip_range()
  mac_string = scan(ip)

  if encrypt:
    data = (file, text)[text]
    perform_encryption(data, mac_string)
  else:
    data = (file, text)[text]
    perform_decryption(data, mac_string)
