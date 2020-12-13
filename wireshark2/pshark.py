import pyshark






cap = pyshark.FileCapture(input_file='capture.pcap', display_filter="",
                          tshark_path='D:\\EXEs\\Wireshark\\tshark.exe')


print(cap[0])

'''
with open('output.txt', 'wb') as f:
    f.write(data)
'''
