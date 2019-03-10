# -*- coding: UTF-8 -*-

import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter import scrolledtext
from tkinter import font, filedialog
from scapy.all import *
import nmap
import socket
import time
import threading

from analyse import scan
from analyse import save

# ===================================================#

# 窗口构建
win = tk.Tk()
win.title("Python 图形用户界面")
win.resizable(0, 0)

#  菜单栏--------------------------------------

# 创建菜单栏功能
menuBar = Menu(win)
win.config(menu=menuBar)

# 创建一个名为文件的菜单项
fileMenu = Menu(menuBar, tearoff=0)
menuBar.add_cascade(label="文件", menu=fileMenu)
fileMenu.add_command(label="打开")


def _save():
	tab1_scr1_log.insert(END, '保存\n')


fileMenu.add_command(label="保存", command=_save)


def _quit():
	"""结束主事件循环"""
	win.quit()  # 关闭窗口
	win.destroy()  # 将所有的窗口小部件进行销毁，应该有内存回收的意思
	exit()


fileMenu.add_command(label="退出", command=_quit)

# 创建一个名为页面的菜单项
viewMenu = Menu(menuBar, tearoff=0)
menuBar.add_cascade(label="页面", menu=viewMenu)
viewMenu.add_command(label="tab1")
viewMenu.add_command(label="tab2")
viewMenu.add_command(label="tab3")
viewMenu.add_separator()
viewMenu.add_command(label="清空消息")
# tab切换控制 --------------------------------------
tabControl = ttk.Notebook(win)  # 构建一个tab

tab1 = ttk.Frame(tabControl)  # Tab1
tabControl.add(tab1, text='网络监控')

tab2 = ttk.Frame(tabControl)  # Tab2
tabControl.add(tab2, text='网络嗅探')

tab3 = ttk.Frame(tabControl)  # Tab3
tabControl.add(tab3, text='端口扫描')

tabControl.pack(expand=1, fill="both")
# -----------------------------------------

# ==========================Tab1控件=============================#
# 线程控制参数
tab1_capture_thread = None
tab1_switch = False
# IP包计数
tab1_IP_number = 1
# 重新开始标志
tab1_restart = True
# 每个ip出现个数
tab1_ip_list = {}
#包储存
tab1_dpkt = None


# ==========================Tab1监控函数=========================#
# sniff终止回调函数
def tab1_stop_sniffing(x):
	global tab1_switch
	return tab1_switch


# 嗅探回调函数
def tab1_pack_callback(packet):
	try:
		global tab1_IP_number
		global tab1_ip_list

		if packet[IP].src in tab1_ip_list:
			tab1_ip_list[packet[IP].src] += 1
		else:
			tab1_ip_list[packet[IP].src] = 1
		# 取出源地址与目的地址
		src = packet[IP].src
		dst = packet[IP].dst
		# 插入tk图形页面tab1_list_tree
		tab1_list_tree.insert("", 'end', tab1_IP_number, text=tab1_IP_number,
		                      values=(tab1_IP_number, src, dst))
		tab1_list_tree.update_idletasks()  # 更新列表，不需要修改
		tab1_IP_number += 1
	except:
		packet.show()
		global tab1_switch
		print('debug:stoping2')
		tab1_switch = True


# packet.show()

def tab1_capture():
	print('debug:capturing....')
	global tab1_dpkt
	tab1_dpkt = sniff(prn=tab1_pack_callback, filter="ip", stop_filter=tab1_stop_sniffing)


# return dpkt
# ============================================================#

# tab1的容器
monty1 = ttk.LabelFrame(tab1, text='监控控制')
monty1.grid(column=0, row=0, padx=2, pady=4)


# 开始按钮函数
def button1_start_click():
	button1_start.configure(state='disabled')  # 禁用按钮1
	button1_pause.configure(state='active')  # 激活按钮2
	button1_quit.configure(state='disabled')  # 禁用按钮3
	button1_save.configure(state='disabled')  # 禁用按钮4
	tab1_scr1_log.insert(END, '开始监控\n')
	print('debug:running')
	global tab1_switch
	global tab1_capture_thread
	global tab1_IP_number
	global tab1_restart
	global tab1_ip_list
	global tab1_list_tree
	if tab1_restart == True:  # 初始化
		tab1_IP_number = 0
		tab1_restart = False
		# 清空已经抓到的数据包列表--------------
		items = tab1_list_tree.get_children()
		for item in items:
			tab1_list_tree.delete(item)
			tab1_list_tree.clipboard_clear()
		tab1_ip_list = {}

	if (tab1_capture_thread is None) or (not tab1_capture_thread.is_alive()):
		tab1_switch = False
		tab1_capture_thread = threading.Thread(target=tab1_capture)
		tab1_capture_thread.start()
	else:
		print('debug:already running')


# 暂停按钮函数
def button1_pause_click():
	button1_start.configure(state='active')  # 激活按钮1
	button1_pause.configure(state='disabled')  # 禁用按钮2
	button1_quit.configure(state='active')  # 激活按钮3
	button1_save.configure(state='active')  # 激活按钮4

	global tab1_switch
	print('debug: pausing')
	tab1_switch = True

	tab1_scr1_log.insert(END, '暂停监控\n')


# 停止按钮函数
def button1_quit_click():
	button1_start.configure(state='active')  # 激活按钮1
	button1_pause.configure(state='disabled')  # 禁用按钮2
	button1_quit.configure(state='disabled')  # 禁用按钮3
	button1_save.configure(state='active')  # 激活按钮4

	global tab1_switch
	global tab1_IP_number
	global tab1_restart
	global tab1_ip_list

	print('debug: stoping')
	tab1_switch = True  # 停止进程
	tab1_restart = True  # 重新开始标志
	time.sleep(1)
	# 统计ip包数目并展示在tab1_scr1_log
	tab1_scr1_log.insert(END, '停止监控\n')
	tab1_scr1_log.insert(END, '共抓到' + str(tab1_IP_number) + '个IP包\n')
	for (key, value) in tab1_ip_list.items():
		tab1_scr1_log.insert(END, '源地址为' + key + '的IP数据包有' + str(value) + '个\n')


# 保存按钮函数
def button1_save_click():
	global tab1_dpkt
	save.save(tab1_dpkt,"tab1")
	tab1_scr1_log.insert(END, '保存\n')


# 按钮1-开始监控按钮
button1_start = ttk.Button(monty1, text="开始监控IP包", width=10, command=button1_start_click)
button1_start.grid(column=0, row=1, ipady=3, pady=5, sticky='W')

# 按钮2-暂停监控按钮
button1_pause = ttk.Button(monty1, text="暂停监听IP包", width=10, state='disabled', command=button1_pause_click)
button1_pause.grid(column=1, row=1, ipady=3, pady=5, sticky='W')

# 按钮3-停止监控按钮
button1_quit = ttk.Button(monty1, text="停止监听IP包", width=10, state='disabled', command=button1_quit_click)
button1_quit.grid(column=2, row=1, ipady=3, pady=5, sticky='W')

# 按钮4-保存监控按钮
button1_save = ttk.Button(monty1, text="保存数据", width=10, state='disabled', command=button1_save_click)
button1_save.grid(column=3, row=1, ipady=3, pady=5, sticky='W')

# 输入栏长宽
tab1_scrolW = 72
tab1_scrolH = 14
tab1_list_tree_row = 6  # listbox高度
tab1_list_tree_columnspan = 6  # listbox文本宽度
# 包列表
tab1_list_tree = ttk.Treeview(monty1, show="headings", height=tab1_scrolH)
tab1_list_tree.grid(column=0, row=tab1_list_tree_row, sticky='WE', columnspan=tab1_list_tree_columnspan)
tab1_list_tree["columns"] = ("No.", "源地址", "Destination")
tab1_list_tree_column_width = [120, 200, 200]
for column_name, column_width in zip(tab1_list_tree["columns"], tab1_list_tree_column_width):
	tab1_list_tree.column(column_name, width=column_width, anchor='w')
	tab1_list_tree.heading(column_name, text=column_name)
# 垂直滚动条
tab1_list_tree_scrolly1 = Scrollbar(monty1)
tab1_list_tree_scrolly1.grid(column=tab1_list_tree_columnspan, row=tab1_list_tree_row, sticky='NS')
tab1_list_tree.configure(yscrollcommand=tab1_list_tree_scrolly1.set)
tab1_list_tree_scrolly1['command'] = tab1_list_tree.yview
# 水平滚动条
tab1_list_tree_scrolly2 = Scrollbar(monty1, orient='horizontal')
tab1_list_tree_scrolly2.grid(column=0, row=tab1_list_tree_row + 1, sticky='NEW', columnspan=tab1_list_tree_columnspan)
tab1_list_tree.configure(xscrollcommand=tab1_list_tree_scrolly2.set)
tab1_list_tree_scrolly2['command'] = tab1_list_tree.xview

# 标签1
ttk.Label(monty1, text="工作日志").grid(column=0, row=tab1_list_tree_row + 1, sticky='W')
# 工作日志
tab1_scr1_log = scrolledtext.ScrolledText(monty1, state='normal', width=tab1_scrolW, height=tab1_scrolH, wrap=tk.WORD)
tab1_scr1_log.grid(column=0, row=tab1_list_tree_row + 2, sticky='WE', columnspan=4)

# ===============================================================#

# ==========================Tab2控件=============================#
# 线程控制参数
tab2_capture_thread = None
tab2_switch = False
# IP包计数
tab2_packet_number = 1
# 重新开始标志
tab2_restart = True
# 包列表
packet_list = []
#包储存
tab2_dpkt = None


# ==========================Tab2监控函数=========================#
def tab2_stop_sniffing(x):
	global tab2_switch
	return tab2_switch


def tab2_pack_callback(packet):
	try:
		if tab2_restart == False:
			src = packet[Ether].src
			dst = packet[Ether].dst
			type = packet[Ether].type
			types = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86dd: 'IPv6', 0x88cc: 'LLDP', 0x891D: 'TTE'}
			if type in types:
				proto = types[type]
			else:
				proto = 'LOOP'  # 协议
			# IP
			if proto == 'IPv4':
				# 建立协议查询字典
				protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP',
				          89: 'OSPF'}
				src = packet[IP].src
				dst = packet[IP].dst
				proto = packet[IP].proto
				if proto in protos:
					proto = protos[proto]
			# tcp
			if TCP in packet:
				protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
				sport = packet[TCP].sport
				dport = packet[TCP].dport
				if sport in protos_tcp:
					proto = protos_tcp[sport]
				elif dport in protos_tcp:
					proto = protos_tcp[dport]
			elif UDP in packet:
				if packet[UDP].sport == 53 or packet[UDP].dport == 53:
					proto = 'DNS'
			length = len(packet)  # 长度
			info = packet.summary()  # 信息
			global tab2_packet_number  # 数据包的编号

			# 包过滤  未完成
			add_flag = 0  # 是否过滤标志
			if chVar_ARP.get() == 1 and proto == 'ARP':  # ARP包过滤
				add_flag = 1
			if chVar_ICMP.get() == 1 and proto == 'ICMP':  # ICMP包过滤
				add_flag = 1
			if chVar_IP.get() == 1 and proto == 'IP':  # IP包过滤
				add_flag = 1
			if chVar_TCP.get() == 1 and proto == 'TCP':  # TCP包过滤
				add_flag = 1
			if chVar_UDP.get() == 1 and proto == 'UDP':  # UDP包过滤
				add_flag = 1
			# 其他包过滤
			if chVar_Others.get() == 1 and add_flag == 1:
				add_flag = 1
			elif chVar_Others.get() == 1 and add_flag == 0:
				add_flag = 1
			elif chVar_Others.get() == 0 and add_flag == 1:
				add_flag = 1
			elif chVar_Others.get() == 0 and add_flag == 0:
				add_flag = 0
			else:
				add_flag = 0

			if add_flag == 1:
				global packet_list
				# 将抓到的包存在列表中
				packet_list.append(packet)
				# 将抓到的包展示在页面tab2_list_tree中
				tab2_list_tree.insert("", 'end', tab2_packet_number, text=tab2_packet_number,
				                      values=(tab2_packet_number, src, dst, proto, length))
				tab2_list_tree.update_idletasks()  # 更新列表，不需要修改
				tab2_packet_number = tab2_packet_number + 1
	except:
		global tab2_switch
		print('debug:except stoping')
		tab2_switch = True


# packet.show()

def tab2_capture():
	print('debug:start capturing....')
	src_str = src_Entered.get()
	dst_str = dst_Entered.get()
	filter_str = ""
	print(src_str)
	if (src_str != ''):
		filter_str = filter_str + "src net " + src_str
		if (dst_str != ''):
			filter_str += ' and '
	if (dst_str != ''):
		filter_str = filter_str + "dst net " + dst_str

	global tab2_dpkt
	tab2_dpkt = sniff(prn=tab2_pack_callback, filter=filter_str, stop_filter=tab2_stop_sniffing)
	print('debug:stoping capturing1....')
	# wrpcap("datas/pkts.pcap", dpkt)


# 数据包解析响应
def on_click_packet_list_tree(event):
	# event.widget获取Treeview对象，调用selection获取选择对象名称,返回结果为字符型元祖
	selected_item = event.widget.selection()
	# 清空tab2_analysis_tree上现有的内容
	tab2_analysis_tree.delete(*tab2_analysis_tree.get_children())
	# 转换为整型
	packet_id = int(selected_item[0]) - 1
	# 取出要分析的数据包
	packet = packet_list[packet_id]
	lines = (packet.show(dump=True)).split('\n')  # dump=True返回字符串，不打出，\n换行符
	last_tree_entry = None
	for line in lines:
		if line.startswith('#'):
			line = line.strip('# ')  # 删除#
			last_tree_entry = tab2_analysis_tree.insert('', 'end', text=line)  # 第一个参数为空表示根节点
		else:
			tab2_analysis_tree.insert(last_tree_entry, 'end', text=line)
		col_width = font.Font().measure(line)
		# 根据新插入数据项的长度动态调整协议解析区的宽度
		if tab2_analysis_tree.column('Dissect', width=None) < col_width:
			tab2_analysis_tree.column('Dissect', width=col_width)


# ============================================================#

# tab2的容器
monty2 = ttk.LabelFrame(tab2, text='嗅探控制')
monty2.grid(column=0, row=0, padx=2, pady=4)


# 开始按钮函数
def button2_start_click():
	button2_start.configure(state='disabled')  # 禁用按钮1
	button2_pause.configure(state='active')  # 激活按钮2
	button2_quit.configure(state='disabled')  # 禁用按钮3
	button2_save.configure(state='disabled')  # 禁用按钮4

	check1.configure(state='disabled')  # 禁用复选框
	check2.configure(state='disabled')  # 禁用复选框
	check3.configure(state='disabled')  # 禁用复选框
	check4.configure(state='disabled')  # 禁用复选框
	check5.configure(state='disabled')  # 禁用复选框
	check6.configure(state='disabled')  # 禁用复选框
	src_Entered.configure(state='disabled')  # 禁用输入框
	dst_Entered.configure(state='disabled')  # 禁用输入框

	print('debug:running')

	global tab2_switch
	global tab2_capture_thread
	global tab2_packet_number
	global tab2_restart
	global tab2_ip_list
	global tab2_list_tree
	if tab2_restart == True:  # 初始化
		tab2_packet_number = 1
		tab2_restart = False
		# 清空已经抓到的数据包列表--------------
		items = tab2_list_tree.get_children()
		for item in items:
			tab2_list_tree.delete(item)
			tab2_list_tree.clipboard_clear()
		tab2_ip_list = {}

	if (tab2_capture_thread is None) or (not tab2_capture_thread.is_alive()):
		tab2_switch = False
		tab2_capture_thread = threading.Thread(target=tab2_capture)
		tab2_capture_thread.start()
	else:
		print('debug:already running')


# 暂停按钮函数
def button2_pause_click():
	button2_start.configure(state='active')  # 激活按钮1
	button2_pause.configure(state='disabled')  # 禁用按钮2
	button2_quit.configure(state='active')  # 激活按钮3
	button2_save.configure(state='active')  # 激活按钮4

	check1.configure(state='active')  # 激活复选框
	check2.configure(state='active')
	check3.configure(state='active')
	check4.configure(state='active')
	check5.configure(state='active')
	check6.configure(state='active')
	src_Entered.configure(state='active')  # 激活输入框
	dst_Entered.configure(state='active')

	global tab2_switch
	print('debug: pausing')
	tab2_switch = True


# 停止按钮函数
def button2_quit_click():
	button2_start.configure(state='active')  # 激活按钮1
	button2_pause.configure(state='disabled')  # 禁用按钮2
	button2_quit.configure(state='disabled')  # 禁用按钮3
	button2_save.configure(state='active')  # 激活按钮4

	check1.configure(state='active')  # 激活复选框
	check2.configure(state='active')
	check3.configure(state='active')
	check4.configure(state='active')
	check5.configure(state='active')
	check6.configure(state='active')
	src_Entered.configure(state='active')  # 激活输入框
	dst_Entered.configure(state='active')

	global tab2_switch
	global tab2_packet_number
	global tab2_restart
	global tab2_ip_list

	print('debug: stoping')
	tab2_switch = True  # 停止进程
	tab2_restart = True  # 重新开始标志
	time.sleep(1)  # 停止1s，等待进程彻底结束


# 保存按钮函数
def button2_save_click():
	global tab2_dpkt
	save.save(tab2_dpkt,"tab2")
	print('debug：保存按钮')


# 下拉框绑定函数
def box_change(*args):
	print(args)
	print(comboxlist.get())
	if comboxlist.get() == 'ARP':
		if chVar_ARP.get() == 1:
			print('debug：关闭ARP过滤')
			check1.deselect()
		else:
			print('debug：只开启ARP过滤')
			check1.select()

			check2.deselect()
			check3.deselect()
			check4.deselect()
			check5.deselect()
			check6.deselect()
	elif comboxlist.get() == 'IP':
		if chVar_IP.get() == 1:
			print('debug：关闭IP过滤')
			check2.deselect()
		else:
			print('debug：只开启IP过滤')
			check2.select()

			check1.deselect()
			check3.deselect()
			check4.deselect()
			check5.deselect()
			check6.deselect()
	elif comboxlist.get() == 'TCP':
		if chVar_TCP.get() == 1:
			print('debug：关闭TCP过滤')
			check3.deselect()
		else:
			print('debug：只开启TCP过滤')
			check3.select()

			check1.deselect()
			check2.deselect()
			check4.deselect()
			check5.deselect()
			check6.deselect()
	elif comboxlist.get() == 'UDP':
		if chVar_UDP.get() == 1:
			print('debug：关闭UDP过滤')
			check4.deselect()
		else:
			print('debug：只开启过滤')
			check4.select()

			check1.deselect()
			check2.deselect()
			check3.deselect()
			check5.deselect()
			check6.deselect()
	elif comboxlist.get() == 'ICMP':
		if chVar_ICMP.get() == 1:
			print('debug：关闭ICMP过滤')
			check5.deselect()
		else:
			print('debug：只开启ICMP过滤')
			check5.select()

			check1.deselect()
			check2.deselect()
			check3.deselect()
			check4.deselect()
			check6.deselect()
	else:
		if chVar_Others.get() == 1:
			print('debug：关闭其他包过滤')
			check6.deselect()
		else:
			print('debug：只开启其他包过滤')
			check6.select()

			check1.deselect()
			check2.deselect()
			check3.deselect()
			check4.deselect()
			check5.deselect()


# 按钮1-开始监控按钮
button2_start = ttk.Button(monty2, text="开始嗅探", width=10, command=button2_start_click)
button2_start.grid(column=0, row=1, ipady=3, sticky='W')

# 按钮2-暂停监控按钮
button2_pause = ttk.Button(monty2, text="暂停嗅探", width=10, state='disabled', command=button2_pause_click)
button2_pause.grid(column=1, row=1, ipady=3, sticky='W')

# 按钮3-停止监控按钮
button2_quit = ttk.Button(monty2, text="停止嗅探", width=10, state='disabled', command=button2_quit_click)
button2_quit.grid(column=2, row=1, ipady=3, sticky='W')

# 按钮4-保存监控按钮
button2_save = ttk.Button(monty2, text="保存数据", width=10, state='disabled', command=button2_save_click)
button2_save.grid(column=3, row=1, ipady=3, sticky='W')

# 构建下拉框
comvalue = tk.StringVar()  # 窗体自带的文本，新建一个值
comboxlist = ttk.Combobox(monty2, textvariable=comvalue)  # 初始化
comboxlist["values"] = ("全选", "ARP", "IP", "TCP", "UDP", "ICMP", "others")
comboxlist.current(0)  # 选择第一个
comboxlist.bind("<<ComboboxSelected>>",box_change)  #绑定事件,(下拉列表框被选中时，绑定box_change()函数)
comboxlist.grid(column=0, row=2, columnspan=2, sticky=tk.W)

check_row = 3
# 构建复选框
chVar_ARP = tk.IntVar()
check1 = tk.Checkbutton(monty2, text="ARP", onvalue=1, offvalue=0, variable=chVar_ARP)
check1.select()
check1.grid(column=0, row=check_row, sticky=tk.W)

chVar_IP = tk.IntVar()
check2 = tk.Checkbutton(monty2, text="IP", variable=chVar_IP)
check2.select()
check2.grid(column=1, row=check_row, sticky=tk.W)

chVar_TCP = tk.IntVar()
check3 = tk.Checkbutton(monty2, text="TCP", variable=chVar_TCP)
check3.select()
check3.grid(column=2, row=check_row, sticky=tk.W)

chVar_UDP = tk.IntVar()
check4 = tk.Checkbutton(monty2, text="UDP", variable=chVar_UDP)
check4.select()
check4.grid(column=3, row=check_row, sticky=tk.W)

chVar_ICMP = tk.IntVar()
check5 = tk.Checkbutton(monty2, text="ICMP", variable=chVar_ICMP)
check5.select()
check5.grid(column=4, row=check_row, sticky=tk.W)

chVar_Others = tk.IntVar()
check6 = tk.Checkbutton(monty2, text="Others", variable=chVar_Others)
check6.select()
check6.grid(column=5, row=check_row, sticky=tk.W)

input_row = 4
# 输入框1
ttk.Label(monty2, text="源IP过滤:").grid(column=0, row=input_row, sticky='W')
src_IP = tk.StringVar()
src_Entered = ttk.Entry(monty2, width=12, textvariable=src_IP)
src_Entered.grid(column=1, row=input_row, columnspan=2, sticky='W')

# 输入框2
ttk.Label(monty2, text="目的IP过滤:").grid(column=3, row=input_row, sticky='W')
dst_IP = tk.StringVar()
dst_Entered = ttk.Entry(monty2, width=12, textvariable=dst_IP)
dst_Entered.grid(column=4, row=input_row, columnspan=2, sticky='W')

# 输入栏长宽
tab2_scrolW = 60
tab2_scrolH = 10
tab2_list_tree_row = 6  # listbox高度
tab2_list_tree_columnspan = 6  # listbox文本宽度
# 包列表
tab2_list_tree = ttk.Treeview(monty2, show="headings", height=tab2_scrolH)
tab2_list_tree.grid(column=0, row=tab2_list_tree_row, sticky='WE', columnspan=tab2_list_tree_columnspan)
tab2_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)  # 点击响应绑定
tab2_list_tree["columns"] = ("No.", "源地址", "目的地址", "协议", "长度")
tab2_list_tree_column_width = [80, 140, 140, 80, 80]
for column_name, column_width in zip(tab2_list_tree["columns"], tab2_list_tree_column_width):
	tab2_list_tree.column(column_name, width=column_width, anchor='w')
	tab2_list_tree.heading(column_name, text=column_name)
# 垂直滚动条
tab2_list_tree_scrolly1 = Scrollbar(monty2)
tab2_list_tree_scrolly1.grid(column=tab2_list_tree_columnspan, row=tab2_list_tree_row, sticky='NS')
tab2_list_tree.configure(yscrollcommand=tab2_list_tree_scrolly1.set)
tab2_list_tree_scrolly1['command'] = tab2_list_tree.yview
# 水平滚动条
tab2_list_tree_scrolly2 = Scrollbar(monty2, orient='horizontal')
tab2_list_tree_scrolly2.grid(column=0, row=tab2_list_tree_row + 1, sticky='NEW', columnspan=tab2_list_tree_columnspan)
tab2_list_tree.configure(xscrollcommand=tab2_list_tree_scrolly2.set)
tab2_list_tree_scrolly2['command'] = tab2_list_tree.xview

# 解析详细
tab2_analysis_tree = ttk.Treeview(monty2, height=tab2_scrolH)
tab2_analysis_tree["columns"] = ("Dissect",)
tab2_analysis_tree.column('Dissect', anchor='w')
tab2_analysis_tree.heading('#0', text='包解析', anchor='w')
tab2_analysis_tree.grid(column=0, row=tab2_list_tree_row + 3, sticky='WE', columnspan=tab2_list_tree_columnspan)
# 垂直滚动条
tab2_analysis_tree_scrolly1 = Scrollbar(monty2)
tab2_analysis_tree_scrolly1.grid(column=tab2_list_tree_columnspan, row=tab2_list_tree_row + 3, sticky='NS')
tab2_analysis_tree.configure(yscrollcommand=tab2_analysis_tree_scrolly1.set)
tab2_analysis_tree_scrolly1['command'] = tab2_analysis_tree.yview
# 水平滚动条
tab2_analysis_tree_scrolly2 = Scrollbar(monty2, orient='horizontal')
tab2_analysis_tree_scrolly2.grid(column=0, row=tab2_list_tree_row + 4, sticky='NEW',
                                 columnspan=tab2_list_tree_columnspan)
tab2_analysis_tree.configure(xscrollcommand=tab2_analysis_tree_scrolly2.set)
tab2_analysis_tree_scrolly2['command'] = tab2_analysis_tree.xview
# ===============================================================#

# ==========================Tab3控件=============================#
# 线程控制参数
tab3_scan_thread = None
tab3_switch = False
# 待扫描主机
tab3_host_ip = '127.0.0.1'
# 主机列表
tab3_host_list = []
# 主机计数
tab3_host_number = 1
# 端口计数
tab3_port_number = 1
# 重新开始标志
tab3_restart = True
# 端口列表
packet_list = []


# ==========================Tab3扫描函数=========================#
# 获取主机ip
def get_localip():
	ip_str = socket.gethostbyname(socket.gethostname())
	return ip_str


# 扫描指定网段在线主机
def nmap_ping_scan(network_segment):
	# 创建一个扫描实例
	nm = nmap.PortScanner()
	# 配置nmap参数
	ping_scan_raw_result = nm.scan(hosts=network_segment, arguments='-v -n -sn')
	# 分析扫描结果，并放入主机清单
	global tab3_host_list
	tab3_host_list = [result['addresses']['ipv4'] for result in ping_scan_raw_result['scan'].values() if
	                  result['status']['state'] == 'up']

	global tab3_host_number
	for host in tab3_host_list:
		if get_localip() == host:
			tab3_list_tree.insert("", 'end', tab3_host_number, text=tab3_host_number,
			                      values=(tab3_host_number, host, '本机'))
			tab3_list_tree.update_idletasks()  # 更新列表，不需要修改
		else:
			tab3_list_tree.insert("", 'end', tab3_host_number, text=tab3_host_number,
			                      values=(tab3_host_number, host, 'up'))
			tab3_list_tree.update_idletasks()  # 更新列表，不需要修改
		tab3_host_number += 1


# 扫描指定主机端口
def scan(network_host):
	print("debug:scan")
	nm = nmap.PortScannerYield()
	port_str = "1-1023"
	port_get = port_Entered.get()
	if port_get != '' and int(port_get) >= 0 and int(port_get) <= 65535:
		port_str = port_get
	try:
		print("debug:start scan")
		for scan_result in nm.scan(hosts=network_host, arguments='-sT -p ' + port_str):
			global tab3_port_number
			global tab3_port_list_tree
			results = scan_result[1]
			for port in results['scan'][network_host]['tcp']:
				tab3_port_list_tree.insert("", 'end', tab3_port_number, text=tab3_port_number,
				                           values=(tab3_port_number, network_host, port,
				                                   results['scan'][network_host]['tcp'][port]['state']))
				tab3_port_list_tree.update_idletasks()  # 更新列表，不需要修改
				tab3_port_number += 1
		print("debug:finish scan")
	except:
		print("debug:可能被防火墙过滤")


# 主机列表单机响应
def on_click_host_list_tree(event):
	selected_item = event.widget.selection()
	global tab3_host_list
	global tab3_host_ip
	tab3_host_ip = tab3_host_list[int(selected_item[0]) - 1]
	host_label.configure(text=tab3_host_ip)


# ============================================================#
# tab3的容器
monty3 = ttk.LabelFrame(tab3, text='端口扫描')
monty3.grid(column=0, row=0, padx=2, pady=4)


def button3_start_host_click():
	global tab3_list_tree
	global tab3_host_number
	# 初始化
	tab3_host_number = 1
	# 清空上次扫描列表数列表
	items = tab3_list_tree.get_children()
	for item in items:
		tab3_list_tree.delete(item)
		tab3_list_tree.clipboard_clear()
	nmap_ping_scan(get_localip() + '/24')


def button3_start_port_click():
	global tab3_port_list_tree
	global tab3_port_number
	# 初始化
	tab3_port_number = 1
	# 清空上次扫描列表数列表
	items = tab3_port_list_tree.get_children()
	for item in items:
		tab3_port_list_tree.delete(item)
		tab3_port_list_tree.clipboard_clear()

	global tab3_host_ip
	# 多线程
	# global tab3_scan_thread
	# if (tab3_scan_thread is None) or (not tab3_scan_thread.is_alive()):
	# 	tab3_scan_thread = threading.Thread(target=scan(tab3_host_ip))
	# 	tab3_scan_thread.start()
	# else:
	# 	print('debug:already running')
	scan(tab3_host_ip)


# 输入框1
ttk.Label(monty3, text="扫描在线主机").grid(column=0, row=3, sticky='W')
# # 按钮1-开始扫描按钮
button3_start = ttk.Button(monty3, text="开始扫描", width=10, command=button3_start_host_click)
button3_start.grid(column=5, row=3, pady=5, sticky='W')
# 输入栏长宽
tab3_scrolW = 60
tab3_scrolH = 10
tab3_list_tree_row = 6  # listbox高度
tab3_list_tree_columnspan = 6  # listbox文本宽度
# 主机列表
tab3_list_tree = ttk.Treeview(monty3, show="headings", height=tab3_scrolH)
tab3_list_tree.grid(column=0, row=tab3_list_tree_row, sticky='WE', columnspan=tab3_list_tree_columnspan)
tab3_list_tree.bind('<<TreeviewSelect>>', on_click_host_list_tree)  # 点击响应绑定
tab3_list_tree["columns"] = ("No.", "主机地址", "状态")
tab3_list_tree_column_width = [140, 240, 140]
for column_name, column_width in zip(tab3_list_tree["columns"], tab3_list_tree_column_width):
	tab3_list_tree.column(column_name, width=column_width, anchor='w')
	tab3_list_tree.heading(column_name, text=column_name)
# 垂直滚动条
tab3_list_tree_scrolly1 = Scrollbar(monty3)
tab3_list_tree_scrolly1.grid(column=tab3_list_tree_columnspan, row=tab3_list_tree_row, sticky='NS')
tab3_list_tree.configure(yscrollcommand=tab3_list_tree_scrolly1.set)
tab3_list_tree_scrolly1['command'] = tab3_list_tree.yview
# 水平滚动条
tab3_list_tree_scrolly2 = Scrollbar(monty3, orient='horizontal')
tab3_list_tree_scrolly2.grid(column=0, row=tab3_list_tree_row + 1, sticky='NEW', columnspan=tab3_list_tree_columnspan)
tab3_list_tree.configure(xscrollcommand=tab3_list_tree_scrolly2.set)
tab3_list_tree_scrolly2['command'] = tab3_list_tree.xview

# 输入框2-1
host_label = ttk.Label(monty3, text="待扫描主机（默认127.0.0.1）")
host_label.grid(column=0, row=tab3_list_tree_row + 2, columnspan=2, sticky='W')
# 输入框2-2
ttk.Label(monty3, text="端口（默认1-1023）:").grid(column=2, row=tab3_list_tree_row + 2, sticky='W')
host_port = tk.StringVar()
port_Entered = ttk.Entry(monty3, width=8, textvariable=host_port)
port_Entered.grid(column=3, row=tab3_list_tree_row + 2, columnspan=1, sticky='W')
# 按钮1-开始扫描按钮
button3_start = ttk.Button(monty3, text="开始扫描", width=10, command=button3_start_port_click)
button3_start.grid(column=5, row=tab3_list_tree_row + 2, pady=5, sticky='W')

# 主机端口列表
tab3_port_list_tree = ttk.Treeview(monty3, show="headings", height=tab3_scrolH)
tab3_port_list_tree.grid(column=0, row=tab3_list_tree_row + 3, sticky='WE', columnspan=tab3_list_tree_columnspan)
# tab3_port_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)  # 点击响应绑定
tab3_port_list_tree["columns"] = ("No.", "主机地址", "端口", "状态")
tab3_port_list_tree_column_width = [80, 200, 160, 80]
for column_name, column_width in zip(tab3_port_list_tree["columns"], tab3_port_list_tree_column_width):
	tab3_port_list_tree.column(column_name, width=column_width, anchor='w')
	tab3_port_list_tree.heading(column_name, text=column_name)
# 垂直滚动条
tab3_port_list_tree_scrolly1 = Scrollbar(monty3)
tab3_port_list_tree_scrolly1.grid(column=tab3_list_tree_columnspan, row=tab3_list_tree_row + 3, sticky='NS')
tab3_port_list_tree.configure(yscrollcommand=tab3_port_list_tree_scrolly1.set)
tab3_port_list_tree_scrolly1['command'] = tab3_port_list_tree.yview
# 水平滚动条
tab3_port_list_tree_scrolly2 = Scrollbar(monty3, orient='horizontal')
tab3_port_list_tree_scrolly2.grid(column=0, row=tab3_list_tree_row + 4, sticky='NEW',
                                  columnspan=tab3_list_tree_columnspan)
tab3_port_list_tree.configure(xscrollcommand=tab3_port_list_tree_scrolly2.set)
tab3_port_list_tree_scrolly2['command'] = tab3_port_list_tree.xview

# ===============================================================#
if __name__ == '__main__':
	# ======================
	# Start GUI
	win.mainloop()
	# ======================
