import nmap

import nmap

hostip = '192.168.10.11'
nm = nmap.PortScanner()
result = nm.scan(hostip, arguments="-sT -p 80-200")
print(result)


for port in result['scan'][hostip]['tcp']:
	print(port)
	print(result['scan'][hostip]['tcp'][port]['state'])
