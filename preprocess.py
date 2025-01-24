import os,shutil
from scapy.all import *
from scapy.utils import PcapReader
import os
from subprocess import Popen, PIPE


import os,shutil
import numpy as np
import pickle

class data(object):
    def __init__(self):
        self.static_feature = []
        self.seq_matirx = []
        self.cert_number = []
        self.urls = []
        self.label = []
        self.image = []
        self.fn = []
        
    def insert(self,static_feature,seq_matirx,cert_number,urls,image,fn,label):
        self.static_feature.append(static_feature)
        self.seq_matirx.append(seq_matirx)
        self.cert_number.append(cert_number)
        self.urls.append(urls)
        self.label.append(label)
        self.image.append(image)
        self.fn.append(fn)

dataT = data()


### First seperate pcaps into flows and store in single pcaps

# command = ["powershell","./split_flow.ps1"]
# process = Popen(command, stdout=PIPE, stderr=PIPE)
                                    

def check_len_1(file, save_path, catg, count):
    min_len = 8
    cc = 1
     
    while True:
        
        save_name = os.path.join(save_path, catg+'_'+str(count)+'.pcap')
        command = ["tshark", "-r", file, "-Y", "tcp.stream eq "+str(cc), "-w", save_name,"-Tfields", 
               "-e", "ip.len"
              ]
        process = Popen(command, stdout=PIPE, stderr=PIPE)
        out, err = process.communicate()
    
        if err:
            warnings.warn("Error reading file: '{}'".format(
                err.decode('utf-8')))
        if (not out == b'') and len(out.decode('utf-8').split('\n')) < min_len:
            cc+=1
            os.remove(save_name)
            if out == b'':
                count += 1
                return count
            continue
        count += 1
        
        cc+=1
#         print(out)
        if out == b'':
            return count
        if count >300:
            return count
        

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import numpy as np
from sklearn.preprocessing import normalize

import re 

import numpy
from PIL import Image
import binascii
import errno    
import os

#session image
def getMatrixfrom_pcap(filename,width):
    with open(filename, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)

    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])  
    # print(len(fh)) 
    rn = len(fh)/width
    # print(fh)
    if len(fh) < 784:
        fh = numpy.append(fh,[0]*(784-len(fh)))
    fh = numpy.reshape(fh[:int(width*width)],(-1,width))  
    fh = numpy.uint8(fh)
    return fh


# def check_len_1(file):
#     min_len = 8
    
#     command = ["tshark", "-r", file, "-Tfields", 
#                "-e", "ip.len",
#               ]
    
    
    
#     for i in range(9,1001):
#         command = ["tshark", "-r", file, "-Y", "tcp.stream eq "+str(i)
#               ]
#         process = Popen(command, stdout=PIPE, stderr=PIPE)
#         out, err = process.communicate()
    
#         if err:
#             warnings.warn("Error reading file: '{}'".format(
#                 err.decode('utf-8')))
# #         print(out)
        
#         packets = out.decode('utf-8').split('\n')
#         print(len(packets))
        

def Find(string): 
    url = re.findall('(?:[-\w.]|(?:%[\da-fA-F]{2}))+', string)
    return [item  for item in url if len(item.split('.')) >=2] 

def check_len(file):
    min_len = 8
    
    command = ["tshark", "-r", file, "-Tfields", 
               "-e", "ip.len",
              ]
    
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output
    out, err = process.communicate()
#     print(out)
    
    if err:
        warnings.warn("Error reading file: '{}'".format(
            err.decode('utf-8')))
        
    packets = out.decode('utf-8').split('\n')

    if len(packets) <min_len:
        return False
    else:
        return True
    
    
    

def url_digger(file):
    url_number = 5
    def get_sec(item):
        return item[1]
    def get_fir(item):
        return item[0]
    
    def url_d(url):
        top_url = ['top','com','xyz','xin','vip','com','net','org','gov','edu','biz','name','info','mobi','pro','travel','club','museum','post','rec','asia','cc','cn','gov','info','net','nom','org','rec','store','web']
        if url.split('.')[-1] in top_url:
            return True
        else:
            return False
        
    packets=rdpcap(file)
    urls_all = []
    for pkt in packets:
        pkt = str(pkt).replace('"', '')
#         pkt = pkt.replace('\\', '')
        urls_all.extend([('.'.join(item.split('.')[-2:]), len('.'.join(item.split('.')[-2:]))) for item in Find(pkt) if url_d(item)])
    urls_all = sorted(urls_all, key=get_sec,reverse=True)
    
    valid_urls = []
        
    for item in urls_all:
        judge = 0
        if len(valid_urls) is 0:
            valid_urls.append([item[0],1])
            continue
        for i in range(len(valid_urls)):
            if item[0] in valid_urls[i][0]:
#                 print(valid_urls[i][1])
                valid_urls[i][1] += 1
                judge = 1
        if judge is 0:
            valid_urls.append([item[0],1])
    valid_urls = sorted(valid_urls,key = get_sec, reverse=True)
    valid_urls =  [get_fir(item) for item in valid_urls]
    valid_urls = (valid_urls + ['0']*max(0,url_number - len(valid_urls)))[:url_number]
    return valid_urls
        

def static_tcp_feature(pcap, bad_tcp_time_key):
    crop_len = 20
    command = ["tshark", "-r", pcap, "-Tfields",
               "-e", "frame.time_epoch",
               "-e", "ip.dst",
               "-e", "tcp.dstport",
               "-e", "ip.proto",
               "-e", "ip.len",
               "-e", "tcp.flags",
               "-e", "ip.src"
              ]
    
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output
    out, err = process.communicate()
#     print(out)
    
    if err:
        warnings.warn("Error reading file: '{}'".format(
            err.decode('utf-8')))
        
#     print(out.decode('utf-8').split('\n')[0].split())
     # Read each packet
    flow = []
    len_seq = []
    flags_seq = []
    time_seq = []
    bad_tcp_seq = [] #0 for normal 1 for bad tcp
    for packet in filter(None, out.decode('utf-8').split('\n')):
        # Get all data from packets
       
        packet = packet.split()
        flow.append(packet)
        #seq of packet len
        len_seq.append(int(packet[4]))
        #seq of flags
        flags_seq.append(int(packet[5][2:]))
        #seq of bad tcp
        if len(bad_tcp_time_key) >0 and packet[0] in bad_tcp_time_key:    
            bad_tcp_seq.append(1)
        else:
            bad_tcp_seq.append(0)
        time_seq.append(float(packet[0])*1000000)
    
    #pkt_arrvial_time
    arrvial_pkt = [itema - itemb for itema,itemb in zip(time_seq[1:],time_seq[:-1])]
    
    #start time and end time
    start_time = time_seq[0]
    end_time = time_seq[-1]
    
    #crop or padding with 0 
    len_seq = (len_seq + [0]*max(0,crop_len-len(len_seq)))[:20]
    flags_seq = (flags_seq + [0]*max(0,crop_len-len(flags_seq)))[:20]
    time_seq = (time_seq + [0.0]*max(0,crop_len-len(time_seq)))[:20]
    bad_tcp_seq = (bad_tcp_seq + [0]*max(0,crop_len-len(bad_tcp_seq)))[:20]
    arrvial_pkt_np = (arrvial_pkt + [0]*max(0,crop_len-len(arrvial_pkt)))[:20]
    
    
    seq_matrix = []
    seq_matrix.append(len_seq)
    seq_matrix.append(flags_seq)
    seq_matrix.append(time_seq)
    seq_matrix.append(bad_tcp_seq)
    seq_matrix.append(arrvial_pkt_np)
    
    seq_matrix = np.array(seq_matrix)
    seq_matrix = normalize(seq_matrix, axis=1, norm='max')
#     print(seq_matrix.shape)
    

        
    #dst ip
#     print(flow)
    if flags_seq[0] == 2:
        dst_ip = int(''.join(flow[0][1].split('.')))
        
    if '192168' in str(dst_ip):
        dst_ip = int(''.join(flow[0][-1].split('.')))

#     print(dst_ip)
    #dst_port
    dst_port = flow[0][2]
    #protocol
    protocol = flow[0][3]
    #max_pkt_len
    max_pkt_len = max(len_seq)
    #min_pkt_len
    min_pkt_len = min(len_seq)
    #avg_pkt_len
    avg_pkt_len = np.array(len_seq).mean()
    #max_pkt_travel
    max_pkt_trvl = max(arrvial_pkt)
    #min_pkt_travel
    min_pkt_trvl = min(arrvial_pkt)
    #avg_pkt_travel
    avg_pkt_trvl = np.array(min_pkt_trvl).mean()
#     print(len_seq)
    static_features = []
    static_features.append(dst_ip)
    static_features.append(dst_port)
    static_features.append(protocol)
    static_features.append(max_pkt_len)
    static_features.append(min_pkt_len)
    static_features.append(avg_pkt_len)
    static_features.append(max_pkt_trvl)
    static_features.append(min_pkt_trvl)
    static_features.append(avg_pkt_trvl)
    static_features.append(start_time)
    static_features.append(end_time)
#     print(len(static_features))  
    return np.array(static_features), seq_matrix
    
    
        
        

def return_cert_info(pcap):
    command = ["tshark", "-r", pcap, "-Tfields", 
               "-e", "tls.handshake.certificate",
              ]
    
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output
    out, err = process.communicate()
#     print(out)
    
    if err:
        warnings.warn("Error reading file: '{}'".format(
            err.decode('utf-8')))
        
#     print(out.decode('utf-8').split('\n')[0].split())
     # Read each packet
    serial = []
    for packet in filter(None, out.decode('utf-8').split('\n')):
#         print(type(packet))
        # Get all data from packets
        packet = packet.split()
#         print(packet)
        if len(packet) != 0 :
            # Get first certificate
            
            certs = packet[0].split(',')
#             print(cert)
            for cert in certs:
                # Transform to hex
#                 print(type(cert))
                cert = bytes.fromhex(cert.replace(':', ''))


                # Read as certificate
                cert = x509.load_der_x509_certificate(cert, default_backend())

    #             print(cert.tbs_certificate_bytes)

                # Set packet as serial number
                if cert.serial_number not in serial:
                    serial.append(cert.serial_number)
            
    return serial
            
            
            
def mark_bad_tcp(pcap):
    command = ["tshark", "-r", pcap, "-Tfields",
               "-e" , "frame.time_epoch",
                
               "-Y", "(tcp.analysis.flags&&!tcp.analysis.window_update&&!tcp.analysis.keep_alive&&!tcp.analysis.keep_alive_ack)||(icmp.type eq 3||icmp.type eq 4||icmp.type eq 5||icmp.type eq 11||icmpv6.type eq 1||icmpv6.type eq 2||icmpv6.type eq 3||icmpv6.type eq 4)||(tcp.flags.reset eq 1)||(sctp.chunk_type eq ABORT)||(( ! ip.dst == 224.0.0.0/4 && ip.ttl < 5 && !pim && !ospf) || (ip.dst == 224.0.0.0/24 && ip.dst != 224.0.0.251 && ip.ttl != 1 && !(vrrp || carp))) || (eth.fcs.status==Bad || ip.checksum.status==Bad || tcp.checksum.status==Bad || udp.checksum.status==Bad || sctp.checksum.status==Bad || mstp.checksum.status==Bad || cdp.checksum.status==Bad || edp.checksum.status==Bad || wlan.fcs.status==Bad || stt.checksum.status==Bad)",
              ]
    
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output
    out, err = process.communicate()
#     print(out)
    
    if err:
        warnings.warn("Error reading file: '{}'".format(
            err.decode('utf-8')))
        
#     print(out.decode('utf-8').split('\n')[0].split())
     # Read each packet
    res = []
    for packet in filter(None, out.decode('utf-8').split('\n')):
        # Get all data from packets
        packet = packet.split()
        res.append(packet)
#         print(packet)
    return res
        
        

src_root = ''
dst_root = ''

catgs = os.listdir(src_root)

for catg in catgs:
    print(catg)
    if not os.path.exists(os.path.join(dst_root,catg)):
        os.mkdir(os.path.join(dst_root,catg))
        
    dst_path = os.path.join(dst_root,catg)
    src_path = os.path.join(src_root,catg)
    
    count = 0
    files = os.listdir(src_path)
    for file in files:
        file = os.path.join(src_path,file)
#         print(file)
        count = check_len_1(file,dst_path, catg, count)
        if count >=300:
            break
        
        
        
    



class data(object):
    def __init__(self):
        self.static_feature = []
        self.seq_matirx = []
        self.cert_number = []
        self.urls = []
        self.label = []
        self.image = []
        self.fn = []
        
    def insert(self,static_feature,seq_matirx,cert_number,urls,image,fn,label):
        self.static_feature.append(static_feature)
        self.seq_matirx.append(seq_matirx)
        self.cert_number.append(cert_number)
        self.urls.append(urls)
        self.label.append(label)
        self.image.append(image)
        self.fn.append(fn)


dataT_backup = dataT


### Load single pcaps and extract features 

import pickle

root = ''

catgs = os.listdir(root)

feature_vectors = []


        
dataT = data()        
        

for catg in catgs:
    root_catg = os.path.join(root,catg)
    files = os.listdir(root_catg)
    print('Handling: '+ catg)
      
    #feature vectors
    cc = 1
    print(catgs.index(catg))
    for file in files:
        file = os.path.join(root_catg,file)
        if not check_len(file):
            continue
        try:
            bad_tcp_time_key = mark_bad_tcp(file) #epoch time => key
            static_feature, seq_matirx = static_tcp_feature(file, bad_tcp_time_key)#return static features and sequence features of each session

            
            cert_number = return_cert_info(file)
#             print(cert_number)
            urls = url_digger(file)

            image = getMatrixfrom_pcap(file,28)
        except:
#             print(file)
            continue
            

        dataT.insert(static_feature,seq_matirx,cert_number,urls,image,file,catgs.index(catg))
        
        
        cc+=1

        if cc % int(len(files)/10) is 0:
            print('{} / {}  '.format(cc,len(files)))
    
        

            
with open("test.pkl",'wb') as f:
    str1 = pickle.dumps(dataT)
    f.write(str1)

        
    