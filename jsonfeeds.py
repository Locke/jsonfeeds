#********************************************************************************
#* 
#* TraCINg (Sensor Part) - prepares Dionaea data for TraCINg server
#* Copyright (C) 2013 	Matthias Gazzari, Annemarie Mattmann, Andre Mougoui,
#*						André Wolski
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* contact	matthias.gazzari@stud.tu-darmstadt.de, mattmann@stud.tu-darmstadt.de,
#* 			andre.wolski@stud.tu-darmstadt.de
#*
#********************************************************************************
#*
#* This code is based on code from the Dionaea project, see
#* http://dionaea.carnivore.it/
#* which is also licensed under GNU General Public License v2.
#*
#********************************************************************************

from dionaea.core import ihandler, g_dionaea

import logging
import requests
import json
import os
import re
import ipaddress
import time

# enable logging
logger = logging.getLogger('jsonfeeds')
logger.setLevel(logging.DEBUG)

# derive from ihandler class
class jsonfeedshandler(ihandler):
	# TODO test requests

	# constructor
	def __init__(self, path):
		logger.debug("%s ready!" % (self.__class__.__name__))
		self.path = path

	# Init
	def start(self):
		ihandler.__init__(self, self.path)
		
		self.submit_url = g_dionaea.config()['modules']['python']['jsonfeeds']['submit_url']
		
		certificate = g_dionaea.config()['modules']['python']['jsonfeeds'].get('certificate', False)
		if certificate:
			self.cert = (certificate['cert'], certificate['key'])
		else:
			self.cert = False

		self.sensor = g_dionaea.config()['modules']['python']['jsonfeeds'].get('sensor', {})

		# delete malware file after download -> True
		self.deleteFile = g_dionaea.config()['modules']['python']['jsonfeeds'].get('delete', False) == "True"
		# TODO verify in config
		self.verify = g_dionaea.config()['modules']['python']['jsonfeeds'].get('verify', False) == "True"

		self.externalIP = {
			"cachetime": int(g_dionaea.config()['modules']['python']['jsonfeeds']['externalIP'].get('cachetime', 0)),
			"lastcheck": 0,
			"ip": g_dionaea.config()['modules']['python']['jsonfeeds']['externalIP'].get('ip', "")
		}
		
		# a cachetime of "0" implies to return self.externalIP["ip"] and to avoid updateExternalIP. So if the ip is set in the config we don't need to updateExternalIP
		if self.externalIP["ip"] != "":
			self.externalIP["cachetime"] = 0
		
		#mapping socket -> attackid
		self.attacks = {}
		'''
		Beispiel Resultat:
		
		self.attacks[icd]["type"] = 32
		self.attacks[icd]["md5hash"] = "d41d8cd98f00b204e9800998ecf8427e"
		self.attacks[icd]["log"] = 
			"connect\n" + 
			"ms_login: user: icd.username, password: icd.password, hostname: icd.hostname, appname: icd.appname, clientname: icd.clientname\n" + 
			"ms_cmd: status: icd.status, cmd: icd.cmd\n"
		'''
	
	
	def getExternalIP(self):
		if(self.externalIP["cachetime"] > 0 and time.time() > (self.externalIP["lastcheck"] + self.externalIP["cachetime"])):
			self.updateExternalIP()
		
		return self.externalIP["ip"]

	def updateExternalIP(self):
		checkip = "http://checkip.dyndns.org/"
		r = requests.get(checkip)
		x = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}", r.text)
		self.externalIP["ip"] = x[0]
		self.externalIP["lastcheck"] = time.time()

	def isValidIP(ip):
		try:
			addr = ipaddress.ip_address(ip)
			return not (addr.is_multicast or addr.is_private or addr.is_unspecified or addr.is_reserved or addr.is_loopback or addr.is_link_local)
		except:
			return False
	
	def translateLocalIP(self, ip):
		if not jsonfeedshandler.isValidIP(ip):
			return self.getExternalIP()
		else:
			return ip
	
	#def handle_incident(self, icd):
	# 	logger.debug("incident origin: %s" % icd.origin)

	# called by append_log and set_type
	def get_attack(self, icd):
		con = icd.con
		if not con in self.attacks:
			self.attacks[con] = {"type":0, "log":"", "md5hash":""}
		return self.attacks[con];

	# called in every handler to store collected data
	def append_log(self, icd, data):
		attack = self.get_attack(icd)
		logger.debug("con: %s" % icd.con)
		logger.debug("attacks in append_log: %s" % self.attacks.keys())		
		#attack["log"].append(data)
		attack["log"] += data + "\n"
		#logger.debug("append data: %s" % data)

	# called in every handler to set type
	def set_type(self, icd, type_id):
		attack = self.get_attack(icd)
		attack["type"] = type_id
		#logger.debug("append data: %s" % data)

	# called by handle_incident_dionaea_download_complete_hash
	def set_md5hash(self, icd):
		attack = self.get_attack(icd)
		attack["md5hash"] = icd.md5hash
		#logger.debug("append md5hash: %s" % md5hash)

	# called by handle_incident_dionaea_connection_free
	def submit_http(self, icd):
		con = icd.con
		src = {"ip":self.translateLocalIP(con.remote.host), "port":con.remote.port}
		dst = {"ip":self.translateLocalIP(con.local.host), "port":con.local.port}
		connection_type = {"transport": con.transport, "protocol": con.protocol}
		
		payload = {"src":src, "dst":dst, "type": self.attacks[con]["type"],
				"connection": connection_type, "log": self.attacks[con]["log"]}

		if self.sensor:
			payload["sensor"] = self.sensor

		if self.attacks[con]["md5hash"] != "":
			payload["md5sum"] = self.attacks[con]["md5hash"]

		logger.debug(" - %s -" % (con.transport))
		logger.debug("POST to %s: %s" % (self.submit_url, json.dumps(payload)))
		# send data via http POST
		if self.cert:
			r = requests.post(self.submit_url, data=json.dumps(payload), verify=self.verify, cert=self.cert)
		else:
			r = requests.post(self.submit_url, data=json.dumps(payload), verify=self.verify)
		
		logger.info("status_code: %i" % (r.status_code))

	# calls submit_http on end of connection
	def handle_incident_dionaea_connection_free(self, icd):
		logger.debug("connection free: %s" % (icd.con.remote.host))
		con=icd.con
		logger.debug("con: %s" % con)
		logger.debug("attacks in con_free: %s" % self.attacks.keys())
		if con in self.attacks:
			try:
				self.submit_http(icd)
			except Exception as e:
				logger.warn("Exception on submit_http: %s " % e)
			del self.attacks[con]
			logger.info("attack %s is done" % con)
		else:
			logger.warn("no attack for %s:%s" % (con.remote.host, con.remote.port))

	def handle_incident_dionaea_connection_tcp_listen(self, icd):
		con=icd.con
		logger.debug("listen tcp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tcp_listen")

	def handle_incident_dionaea_connection_tls_listen(self, icd):
		con=icd.con
		logger.debug("listen tls connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tls_listen")

	def handle_incident_dionaea_connection_tcp_connect(self, icd):
		con=icd.con
		logger.debug("connect tcp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tcp_connect")

	def handle_incident_dionaea_connection_tls_connect(self, icd):
		con=icd.con
		logger.debug("connect tls connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tls_connect")

	def handle_incident_dionaea_connection_udp_connect(self, icd):
		con=icd.con
		logger.debug("connect udp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "udp_connect")

	def handle_incident_dionaea_connection_tcp_accept(self, icd):
		con=icd.con
		logger.debug("accept tcp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tcp_accept")

	def handle_incident_dionaea_connection_tls_accept(self, icd):
		con=icd.con
		logger.debug("accept tls connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tls_accept")

	def handle_incident_dionaea_connection_tcp_reject(self, icd):
		con=icd.con
		logger.debug("reject tcp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 11)
		self.append_log(icd, "tcp_reject")

	def handle_incident_dionaea_connection_tcp_pending(self, icd):
		con=icd.con
		logger.debug("pending tcp connection from %s:%i to %s:%i" % 
			(con.remote.host, con.remote.port, con.local.host, con.local.port))
		self.set_type(icd, 10)
		self.append_log(icd, "tcp_pending")

	def handle_incident_dionaea_modules_python_smb_dcerpc_request(self, icd):
		con=icd.con
		logger.debug("SMB dcercp request: %s" % icd.uuid)
		smb = "smb_request: uuid: %s, opnum: %s" % (icd.uuid, icd.opnum)
		self.set_type(icd, 40)
		self.append_log(icd, smb)

	def handle_incident_dionaea_modules_python_smb_dcerpc_bind(self, icd):
		con=icd.con
		logger.debug("SMB dcercp bind: %s" % icd.uuid)
		smb = "smb_bind: uuid: %s, transfersyntax: %s" % (icd.uuid, icd.transfersyntax)
		self.set_type(icd, 40)
		self.append_log(icd, smb)

	def handle_incident_dionaea_module_emu_profile(self, icd):
		con = icd.con
		logger.debug("EMU profile: %s" % icd.profile)
		emu = "emu: profile: %s" % (icd.profile)
		self.set_type(icd, 20)
		self.append_log(icd, emu)

	def handle_incident_dionaea_download_complete_hash(self, icd):
		con = icd.con
		logger.debug("DL complete hash: %s" % icd.url)
		self.set_md5hash(icd)
		dch = "dl_hash: url: %s, md5hash: %s" % (icd.url, icd.md5hash)
		# TODO: Der Typ sollte bereits gesetzt sein; beobachten ob es wirklich so ist
		self.append_log(icd, dch)
		# delete malware file
		if self.deleteFile:
			try:			
				os.remove(icd.file)
			except Exception as e:
				logger.warn("Exception on deleting file: %s " % e)

	def handle_incident_dionaea_modules_python_mssql_login(self, icd):
		con = icd.con
		logger.debug("MS sql login: %s,%s" % (icd.username, icd.password))
		mslogin = "mssql_login: username: %s, password: %s, hostname: %s, appname: %s, clientname: %s" % (icd.username, icd.password, icd.hostname, icd.appname, icd.clientname)
		self.set_type(icd, 32)
		self.append_log(icd, mslogin)

	def handle_incident_dionaea_modules_python_mssql_cmd(self, icd):
		con = icd.con
		logger.debug("MS sql cmd: %s" % icd.cmd)
		mscmd = "mssql_cmd: status: %s, cmd: %s" % (icd.status, icd.cmd)
		self.set_type(icd, 32)
		self.append_log(icd, mscmd)


	def handle_incident_dionaea_modules_python_mysql_login(self, icd):
		con = icd.con
		logger.debug("MY sql login: %s,%s" % (icd.username, icd.password))
		mylogin = "mysql_login: username: %s, password: %s" % (icd.username, icd.password)
		self.set_type(icd, 31)
		self.append_log(icd, mylogin)

	def handle_incident_dionaea_modules_python_mysql_command(self, icd):
		con = icd.con
		logger.debug("MY sql command: %s" % icd.command)
		mycmd = "mysql_cmd: %s" % icd.command
		if hasattr(icd, 'args'):
			mycmd += ", args: " + ", ".join(icd.args)
		self.set_type(icd, 31)
		self.append_log(icd, mycmd)

	# VoiP attacks
	def handle_incident_dionaea_modules_python_sip_command(self, icd):
		self.set_type(icd, 50)

		sip_cmds = "sip_cmd: method: %s, call_id: %s, user_agent: %s, allow: %s" % (icd.method, icd.call_id, icd.user_agent, icd.allow)
		self.append_log(icd, sip_cmds)

		def add_addr(_type, addr):
			cmdaddr = "%s: display_name: %s, scheme: %s, user: %s, password: %s, host: %s, port: %s" % (_type, addr['display_name'],	addr['uri']['scheme'], addr['uri']['user'],
					addr['uri']['password'], addr['uri']['host'], addr['uri']['port'])
			self.append_log(icd, cmdaddr)

		add_addr('addr', icd.get('addr'))
		add_addr('to', icd.get('to'))
		add_addr('contact', icd.get('contact'))

		for i in icd.get('from'):
			add_addr('from', i)

		def add_via(via):
			via = "via: protocol: %s, address: %s, port: %s" % (via['protocol'], via['address'], via['port'])
			self.append_log(icd, via)

		for i in icd.get('via'):
			add_via(i)

		def add_sdp(sdp):
			def add_origin(o):
				origin = "origin: username: %s, sess_id: %s, sess_version: %s, nettype: %s, addrtype: %s, unicast_address: %s" % (o['username'], o['sess_id'], o['sess_version'],
						o['nettype'], o['addrtype'], o['unicast_address'])
				self.append_log(icd, origin)

			def add_condata(c):
				cdata = "connection_data: nettype: %s, addrtype: %s, connection_address: %s, ttl: %s, number_of_addresses: %s" % (c['nettype'], c['addrtype'], c['connection_address'],
						c['ttl'], c['number_of_addresses'])
				self.append_log(icd, cdata)
			def add_media(c):
				media = "sdp_media: media: %s, port: %s, number_of_ports: %s, proto: %s" % (c['media'], c['port'], c['number_of_ports'], c['proto'])
				self.append_log(icd, media)

			if 'o' in sdp:
				add_origin(sdp['o'])
			if 'c' in sdp:
				add_condata(sdp['c'])
			if 'm' in sdp:
				for i in sdp['m']:
					add_media(i)

		if hasattr(icd,'sdp') and icd.sdp is not None:
			add_sdp(icd.sdp)

	# wird nicht benutzt; muss explizit in dionaea aktiviert werden
	def handle_incident_dionaea_modules_python_p0f(self, icd):
		con = icd.con
		logger.debug("p0f: %s, %s" % (icd.genre, icd.link))
		p0f = "p0f: genre: %s, link: %s, detail: %s, uptime: %s, tos: %s, dist: %s, nat: %s, fw: %s" % (icd.genre, icd.link, icd.detail, icd.uptime, icd.tos, icd.dist, icd.nat, icd.fw)
		self.append_log(icd, p0f)

	# wird nicht benutzt; muss explizit in dionaea aktiviert werden
	def handle_incident_dionaea_modules_python_virustotal_report(self, icd):
		f = open(icd.path, mode='r')
		j = json.load(f)

		if j['result'] == 1: # file was known to virustotal
			virust = "virustotal: md5hash: %s, permalink: %s, report[0]: %s" % (icd.md5hash, j['permalink'], j['report'][0])
			self.append_log(icd, virust)
			logger.debug("Virustotal %s" % icd.md5hash)
			avscans = ""
			scans = j['report'][1]
			for av in scans:
				res = scans[av]
				# not detected = '' -> NULL
				if res != '':
					avscans += "%s %s" % (av, res)
			self.append_log(icd, avscans)
			#logger.debug("scanner {} result {}".format(av,scans[av]))
