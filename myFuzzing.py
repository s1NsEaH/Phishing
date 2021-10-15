#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import sys
import socket
import signal
import time
import threading
from os import path
import smtplib
import queue
from urllib import request
from urllib.error import HTTPError
import json

def p_err(msg):
	print(str('\033[93m'+msg+'\033[0m'), file = sys.stderr, flush = True)
	pass
try:
	from ipwhois import IPWhois
	MODULE_IPWHOIS = True
except ImportError:
	MODULE_IPWHOIS = False
	p_err('No Module ipwhois')

try:
	from bs4 import BeautifulSoup
	MODULE_BS4 = True
except ImportError:
	MODULE_BS4 = False
	p_err('No Module bs4')

try:
	import whois
	MODULE_WHOIS = True
except ImportError:
	MODULE_WHOIS = False
	p_err('No Module whois')

try:
	from dns.resolver import Resolver, NXDOMAIN, NoNameservers
	import dns.rdatatype
	from dns.exception import DNSException
	MODULE_DNSPYTHON = True
except ImportError:
	MODULE_DNSPYTHON = False

try:
	from cryptography.x509.oid import NameOID
	from cryptography import x509
	from OpenSSL import SSL
	MODULE_OPENSSL = True
except ImportError:
	MODULE_OPENSSL = False
	p_err('No Module OpenSSL')

try:
	import requests
	requests.packages.urllib3.disable_warnings()
	MODULE_REQUESTS = True
except ImportError:
	MODULE_REQUESTS = False
	p_err('No Module Requests')

try:
	import idna
except ImportError:
	class idna:
		@staticmethod
		def decode(domain):
			return domain.encode().decode('idna')
		@staticmethod
		def encode(domain):
			return domain.encode('idna')

VALID_FQDN_REGEX = re.compile(r'(?=^.{4,253}$)(^((?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z0-9-]{2,63}$)', re.IGNORECASE)

REQUEST_TIMEOUT_DNS = 2.5
REQUEST_RETRIES_DNS = 2
REQUEST_TIMEOUT_HTTP = 5
REQUEST_TIMEOUT_SMTP = 5
THREAD_COUNT_DEFAULT = 10
USERAGENT = "Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36"

class urlParser():
	def __init__(self, url):
		if '://' not in url:
			self.url = 'http://' + url
		else:
			self.url = url
		self.scheme = ''
		self.authority = ''
		self.domain = ''
		self.__parse()

	def __parse(self):
		re_rfc3986_enhanced = re.compile(
			r'''
			^
			(?:(?P<scheme>[^:/?#\s]+):)?
			(?://(?P<authority>[^/?#\s]*))?
			$
			''', re.MULTILINE | re.VERBOSE
			)
		m_uri = re_rfc3986_enhanced.match(self.url)

		if m_uri:
			if m_uri.group('scheme'):
				if m_uri.group('scheme').startswith('http'):
					self.scheme = m_uri.group('scheme')
				else:
					self.scheme = 'http'

			if m_uri.group('authority'):
				self.authority = m_uri.group('authority')
				self.domain = self.authority.split(':')[0].lower()
				if not self.__validate_domain(self.domain):
					raise ValueError('Invalid domain name')

	def __validate_domain(self, domain):
		if len(domain) > 253:
			return False
		if VALID_FQDN_REGEX.match(domain):
			try:
				_ = idna.decode(domain)
			except Exception:
				return False
			else:
				return True
		return False

	def full_uri(self):
		return self.scheme + '://' + self.domain

class makeDomainFuzz():
	def __init__(self, domain, tld_dictionary = []):
		self.subdomain, self.domain, self.tld = self.domain_tld(domain)
		self.domain = idna.decode(self.domain)
		self.tld_dictionary = list(tld_dictionary)
		self.domains = []
		self.qwerty = {
			'1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
			'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
			'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
			'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
			}
		self.tenkey = {
			'a': 'bc', 'b': 'ac', 'c': 'ab', 'd': 'ef', 'e': 'df', 'f': 'de', 'g': 'hi', 'h': 'gi', 'i': 'gh', 'j': 'kl', 'k': 'jl', 'l': 'jk', 'm': 'no',
			'n': 'mo', 'o': 'nm', 'p': 'qrs', 'q': 'prs', 'r':'pqs', 's': 'pqr', 't': 'uv', 'u': 'tv', 'v': 'tu', 'w': 'xyz', 'x': 'wyz', 'y': 'wxz', 'z': 'wxy'
			}

		self.keyboards = [self.qwerty, self.tenkey]
		self.glyphs = {
			'2': ['ƻ'],
			'5': ['ƽ'],
			'a': ['à', 'á', 'à', 'â', 'ã', 'ä', 'å', 'ɑ', 'ạ', 'ǎ', 'ă', 'ȧ', 'ą'],
			'b': ['d', 'lb', 'ʙ', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ƅ'],
			'c': ['e', 'ƈ', 'ċ', 'ć', 'ç', 'č', 'ĉ', 'ᴄ'],
			'd': ['b', 'cl', 'dl', 'ɗ', 'đ', 'ď', 'ɖ', 'ḑ', 'ḋ', 'ḍ', 'ḏ', 'ḓ'],
			'e': ['c', 'é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ě', 'ė', 'ẹ', 'ę', 'ȩ', 'ɇ', 'ḛ'],
			'f': ['ƒ', 'ḟ'],
			'g': ['q', 'ɢ', 'ɡ', 'ġ', 'ğ', 'ǵ', 'ģ', 'ĝ', 'ǧ', 'ǥ'],
			'h': ['lh', 'ĥ', 'ȟ', 'ħ', 'ɦ', 'ḧ', 'ḩ', 'ⱨ', 'ḣ', 'ḥ', 'ḫ', 'ẖ'],
			'i': ['1', 'l', 'í', 'ì', 'ï', 'ı', 'ɩ', 'ǐ', 'ĭ', 'ỉ', 'ị', 'ɨ', 'ȋ', 'ī', 'ɪ'],
			'j': ['ʝ', 'ǰ', 'ɉ', 'ĵ'],
			'k': ['lk', 'ik', 'lc', 'ḳ', 'ḵ', 'ⱪ', 'ķ', 'ᴋ'],
			'l': ['1', 'i', 'ɫ', 'ł'],
			'm': ['n', 'nn', 'rn', 'rr', 'ṁ', 'ṃ', 'ᴍ', 'ɱ', 'ḿ'],
			'n': ['m', 'r', 'ń', 'ṅ', 'ṇ', 'ṉ', 'ñ', 'ņ', 'ǹ', 'ň', 'ꞑ'],
			'o': ['0', 'ȯ', 'ọ', 'ỏ', 'ơ', 'ó', 'ö', 'ᴏ'],
			'p': ['ƿ', 'ƥ', 'ṕ', 'ṗ'],
			'q': ['g', 'ʠ'],
			'r': ['ʀ', 'ɼ', 'ɽ', 'ŕ', 'ŗ', 'ř', 'ɍ', 'ɾ', 'ȓ', 'ȑ', 'ṙ', 'ṛ', 'ṟ'],
			's': ['ʂ', 'ś', 'ṣ', 'ṡ', 'ș', 'ŝ', 'š', 'ꜱ'],
			't': ['ţ', 'ŧ', 'ṫ', 'ṭ', 'ț', 'ƫ'],
			'u': ['ᴜ', 'ǔ', 'ŭ', 'ü', 'ʉ', 'ù', 'ú', 'û', 'ũ', 'ū', 'ų', 'ư', 'ů', 'ű', 'ȕ', 'ȗ', 'ụ'],
			'v': ['ṿ', 'ⱱ', 'ᶌ', 'ṽ', 'ⱴ', 'ᴠ'],
			'w': ['vv', 'ŵ', 'ẁ', 'ẃ', 'ẅ', 'ⱳ', 'ẇ', 'ẉ', 'ẘ', 'ᴡ'],
			'x': ['ẋ', 'ẍ'],
			'y': ['ʏ', 'ý', 'ÿ', 'ŷ', 'ƴ', 'ȳ', 'ɏ', 'ỿ', 'ẏ', 'ỵ'],
			'z': ['ʐ', 'ż', 'ź', 'ᴢ', 'ƶ', 'ẓ', 'ẕ', 'ⱬ']
			}

	@staticmethod
	def domain_tld(domain):
		try:
			from tld import parse_tld
		except ImportError:
			ctld = ['org', 'com', 'net', 'gov', 'edu', 'co', 'mil', 'nom', 'ac', 'info', 'biz']
			d = domain.rsplit('.', 3)
			if len(d) == 2:
				return '', d[0], d[1]
			if len(d) > 2:
				if d[-2] in ctld:
					return '.'.join(d[:-3]), d[-3], '.'.join(d[-2:])
				else:
					return '.'.join(d[:-2]), d[-2], d[-1]
		else:
			d = parse_tld(domain, fix_protocol = True)[::-1]
			if d[1:] == d[:-1] and None in d:
				d = tuple(domain.rsplit('.', 2))
				d = ('',) * (3 - len(d)) + d
			return d

	def __postprocess(self):
		def punycode(domain):
			try:
				return idna.encode(domain).decode()
			except Exception:
				return ''
		for idx, domain in enumerate(map(punycode, [x.get('domain-name') for x in self.domains])):
			self.domains[idx]['domain-name'] = domain
		seen = set()
		filtered = []
		for domain in self.domains:
			name = domain.get('domain-name')
			if VALID_FQDN_REGEX.match(name) and name not in seen:
				filtered.append(domain)
				seen.add(name)
		self.domains = filtered

	def __bitsquatting(self):
		result = []
		maskBit = [1, 2, 4, 8, 16, 32, 64, 128]
		chars = set('abcdefghijklmnopqrstuvwxyz0123456789-')
		for i, c in enumerate(self.domain):
			for mask in maskBit:
				b = chr(ord(c) ^ mask)
				if b in chars:
					result.append(self.domain[:i] + b + self.domain[i+1:])
		return result

	def __homoglyph(self):
		def mix(domain):
			result = set()
			glyphs = self.glyphs
			for w in range(1, len(domain)):
				for i in range(len(domain) - w + 1):
					pre = domain[:i]
					win = domain[i:i+w]
					suf = domain[i+w:]
					for c in win:
						for g in glyphs.get(c, []):
							result.add(pre + win.replace(c, g) + suf)
				return result
		result1 = mix(self.domain)
		result2 = set()
		for r in result1:
			result2.update(mix(r))
		return list(result1 | result2)

	def __hyphenation(self):
		return [self.domain[:i] + '-' + self.domain[i:] for i in range(1, len(self.domain))]

	def __insertion(self):
		result = set()
		for i in range(1, len(self.domain) - 1):
			prefix, orig_c, suffix = self.domain[:i], self.domain[i], self.domain[i+1:]
			for c in (c for keys in self.keyboards for c in keys.get(orig_c, [])):
				result.add(prefix + c + orig_c + suffix)
				result.add(prefix + orig_c + c + suffix)
		return list(result)

	def __omission(self):
		return list({self.domain[:i] + self.domain[i+1:] for i in range(len(self.domain))})

	def __repetition(self):
		return list({self.domain[:i] + c + self.domain[i:] for i, c in enumerate(self.domain)})

	def __replacement(self):
		result = set()
		for i, c in enumerate(self.domain):
			pre = self.domain[:i]
			suf = self.domain[i+1:]
			for layout in self.keyboards:
				for r in layout.get(c, ''):
					result.add(pre + r + suf)
		return list(result)

	def __subdomain(self):
		result = []
		for i in range(1, len(self.domain) - 1):
			if self.domain[i] not in ['-', '.'] and self.domain[i-1] not in ['-', '.']:
				result.append(self.domain[:i] + '.' + self.domain[i:])
		return result

	def __transposition(self):
		return list({self.domain[:i] + self.domain[i+1] + self.domain[i] + self.domain[i+2:] for i in range(len(self.domain) - 1)})

	def __vowel_swap(self):
		vowels = 'aeiou'
		result = []
		for i in range(0, len(self.domain)):
			for vowel in vowels:
				if self.domain[i] in vowels:
					result.append(self.domain[:i] + vowel + self.domain[i+1:])
		return list(set(result))

	def __addition(self):
		return [self.domain + chr(i) for i in range(97, 123)]


	def __tld(self):
		if self.tld in self.tld_dictionary:
			self.tld_dictionary.remove(self.tld)
		return list(set(self.tld_dictionary))

	def generate(self):
		self.domains.append({'class': 'original', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, self.tld]))})
		class_name = self.__class__.__name__
		for name in [
			'addition', 'bitsquatting', 'homoglyph', 'hyphenation', 'insertion',
			'omission', 'repetition', 'replacement', 'subdomain', 'transposition', 'vowel-swap',
		]:
			f_name = name.replace('-', '_')
			f = getattr(self, f'_{class_name}__{f_name}')
			for domain in f():
				self.domains.append({'class': name, 'domain-name': '.'.join(filter(None, [self.subdomain, domain, self.tld]))})

		for tld in self.__tld():
			self.domains.append({'class': 'tld-swap', 'domain-name': '.'.join(filter(None, [self.subdomain, self.domain, tld]))})

		if '.' in self.tld:
			self.domains.append({'class': 'tld-swap', 'domain-name': self.domain + '.' + self.tld.split('.')[-1]})
			self.domains.append({'class': 'various', 'domain-name': self.domain + self.tld})

		if '.' not in self.tld:
			self.domains.append({'class': 'various', 'domain-name': self.domain + self.tld + '.' + self.tld})

		if self.tld != 'com' and '.' not in self.tld:
			self.domains.append({'class': 'various', 'domain-name': self.domain + '-' + self.tld + '.com'})

		self.__postprocess()

	def permutations(self, registered = False):
		domains = []
		if registered:
			domains = [x.copy() for x in self.domains if len(x) > 2]
		else:
			domains = self.domains.copy()
		return domains

class domainThread(threading.Thread):
	def __init__(self, queue):
		threading.Thread.__init__(self)
		self.jobs = queue
		self.kill_received = False
		self.debug = False
		self.uri_scheme = 'http'
		self.option_extdns = False
		self.get_certificate = False

		self.nameservers = []
		self.useragent = USERAGENT

	def __debug(self, msg):
		if self.debug:
			print(str(msg), file = sys.stderr, flush = True)

	def __get_certificate(self, hostname, port):
		try:
			hostname_idna = idna.encode(hostname)
			sock = socket.socket()
			sock.connect((hostname, port))
			peername = sock.getpeername()
			ctx = SSL.Context(SSL.SSLv23_METHOD)
			ctx.check_hostname = False
			ctx.verify_mode = SSL.VERIFY_NONE
			sock_ssl = SSL.Connection(ctx, sock)
			sock_ssl.set_connect_state()
			sock_ssl.set_tlsext_host_name(hostname_idna)
			sock_ssl.do_handshake()
			cert = sock_ssl.get_peer_certificate()
			crypto_cert = cert.to_cryptography()
			sock_ssl.close()
			sock.close()
			return crypto_cert
		except:
			pass

	def __get_title(self, hostname):
		if MODULE_BS4:
			headers = {'User-Agent': self.useragent}
			try:
				html = request.urlopen('http://'+hostname, timeout=REQUEST_TIMEOUT_HTTP, data=bytes(json.dumps(headers), encoding="utf-8"))
				soup = BeautifulSoup(html, 'html.parser')
				title = soup.find('title')
				return title
			except HTTPError as code:
				if code.status == 403:
					req = requests.get(self.uri_scheme + '://' + hostname, timeout=REQUEST_TIMEOUT_HTTP, headers=headers, verify=False)
					soup = BeautifulSoup(req.content, 'html.parser')
					time.sleep(2.0)
					return soup.title.string
			except Exception as e:
				self.__debug(e)
				pass
	'''
	def __get_country(self):
		if dns_a is True:
			try:
				obj = IPWhois(domain['dns-a'][0])
				results = obj.lookup_rws()
				country = (results['nets'][0]['country'])
			except Exception as e:
				self.__debug(e)
				pass
			else:
				if country:
					domain['country'] = country
	'''
	def __mxcheck(self, mx, from_domain, to_domain):
		from_addr = 'IamBob1997@' + from_domain
		to_addr = 'YouAreAlice1997@' + to_domain
		try:
			smtp = smtplib.SMTP(mx, 25, timeout = REQUEST_TIMEOUT_SMTP)
			smtp.sendmail(from_addr, to_addr, 'I wish you well')
			smtp.quit()

		except Exception:
			return False
		else:
			return True

	def __answer_to_list(self, answers):
		return sorted([str(x).split(' ')[-1].rstrip('.') for x in answers])

	def stop(self):
		self.kill_received = True

	def run(self):
		if self.option_extdns:
			if self.nameservers:
				resolv = Resolver(configure = False)
				resolv.nameservers = self.nameservers
			else:
				resolv = Resolver()
				resolv.search = []

			resolv.lifetime = REQUEST_TIMEOUT_DNS * REQUEST_RETRIES_DNS
			resolv.timeout = REQUEST_TIMEOUT_DNS
			EDNS_PAYLOAD = 1232
			resolv.use_edns(edns = True, ednsflags = 0, payload = EDNS_PAYLOAD)

			if hasattr(resolv, 'resolve'):
				resolve = resolv.resolve
			else:
				resolve = resolv.query

		while not self.kill_received:
			try:
				domain = self.jobs.get(block = False)
			except queue.Empty:
				self.kill_received = True
				return
			if self.option_extdns:
				nxdomain = False
				dns_ns = False
				dns_a = False
				dns_mx = False
				try:
					domain['dns-ns'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype = dns.rdatatype.NS))
					dns_ns = True
				except NXDOMAIN:
					nxdomain = True
				except NoNameservers:
					domain['dns-ns'] = ['!ServFail']
				except DNSException as e:
					self.__debug(e)

				if nxdomain is False:
					try:
						domain['dns-a'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype = dns.rdatatype.A))
						dns_a = True
					except NoNameservers:
						domain['dns-a'] = ['!ServFail']
					except DNSException as e:
						self.__debug(e)

				if nxdomain is False and dns_ns is True:
					try:
						domain['dns-mx'] = self.__answer_to_list(resolve(domain['domain-name'], rdtype = dns.rdatatype.MX))
						dns_mx = True
					except NoNameservers:
						domain['dns-mx'] = ['!ServFail']
					except	DNSException as e:
						self.__debug(e)
			else:
				try:
					ip = socket.getaddrinfo(domain['domain-name'], 80)
				except socket.gaierror as e:
					if e.errno == -3:
						domain['dns-a'] = ['!servFail']
				except Exception as e:
					self.__debug(e)

				else:
					domain['dns-a'] = list()
					for j in ip:
						if '.' in j[4][0]:
							domain['dns-a'].append(j[4][0])
					domain['dns-a'] = sorted(domain['dns-a'])
					dns_a = True

			if self.get_title:
				title = self.__get_title(domain['domain-name'])
				if title:
					domain['title'] = str(title).replace(',','')
			if self.get_certificate:
				hostinfo = self.__get_certificate(domain['domain-name'], 443)
				if hostinfo:
					domain['notbefore'] = str(hostinfo.not_valid_before).split(' ')[0]
					issuer = hostinfo.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
					try:
						domain['issuer'] = str(issuer[0].value).replace(',','')
					except:
						pass
			self.jobs.task_done()

def create_csv(idx, domains = []):
	csv = []
	if idx == 0:
		csv = ['class,domain,dns-a,dns-mx,dns-ns,country,whois-registrar,whois-created,notbefore,issuer,title']
	for domain in domains:
		csv.append(','.join([domain.get('class'), domain.get('domain-name'),
		';'.join(domain.get('dns-a', [])),
		';'.join(domain.get('dns-mx', [])),
		';'.join(domain.get('dns-ns', [])),
		domain.get('country', ''), domain.get('whois-registrar', ''), domain.get('whois-created', ''), domain.get('notbefore', ''), domain.get('issuer', ''),domain.get('title', '')]))
	return '\n'.join(csv)

def main():

	def _exit(code):
		sys.exit(code)

	threads = []
	def p_err(msg):
		print(str(msg), file = sys.stderr, flush = True)

	def signal_handler(signal, frame):
		print('\nStopping threads... ', file=sys.stderr, end='', flush=True)
		for worker in threads:
			worker.stop()
			worker.join()
		print('Done', file=sys.stderr)
		_exit(0)

	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	nameservers = ['8.8.8.8']

	tld = "./tldlist.txt"
	if not path.exists(tld):
		p_err('dictionary file not found: %s' % tld)
	with open(tld) as f:
		tld = set(f.read().splitlines())
		tld = [x for x in tld if x.isalpha()]

	hosts = ['shinhan.com', 'kbstar.com']
	for idx, host in enumerate(hosts):
		try:
			url = urlParser(host) if host.isascii() else urlParser(idna.encode(host).decode())
		except Exception as e:
			p_err('invalid domain name: ' + host)
		fuzz = makeDomainFuzz(url.domain, tld_dictionary=tld)
		fuzz.generate()
		domains = fuzz.domains
		p_err('%d. Processing %d permutations ' % (idx, len(domains)))
		jobs = queue.Queue()

		for i in range(len(domains)):
			jobs.put(domains[i])

		for _ in range(THREAD_COUNT_DEFAULT):
			worker = domainThread(jobs)
			worker.setDaemon(True)
			worker.uri_scheme = url.scheme
			worker.domain_init = url.domain

			if MODULE_DNSPYTHON:
				worker.option_extdns = True

			worker.get_certificate = True
			worker.get_title = True
			worker.nameservers = nameservers
			worker.useragent = USERAGENT
			worker.debug = True
			worker.start()
			threads.append(worker)

		qperc = 0
		while not jobs.empty():
			qcurr = 100 * (len(domains) - jobs.qsize()) / len(domains)
			if qcurr - 20 >= qperc:
				qperc = qcurr
				p_err('%u%%' % qperc)
			time.sleep(1.0)

		for worker in threads:
			worker.stop()
			worker.join()

		domains = fuzz.permutations(registered=True, dns_all=False)

		if MODULE_WHOIS:
			for domain in domains:
				if len(domain) > 2:
					try:
						_, dom, tld = fuzz.domain_tld(domain['domain-name'])
						whoisq = whois.whois('.'.join([dom, tld]))
					except Exception as e:
						p_err(e)
					else:
						if whoisq is None:
							continue
						if whoisq.creation_date and isinstance(whoisq.creation_date, list):
							domain['whois-created'] = str(whoisq.creation_date[0]).split(' ')[0]
						else:
							domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
						if whoisq.registrar:
							domain['whois-registrar'] = str(whoisq.registrar).replace(",","")
						if whoisq.country:
							domain['country'] = str(whoisq.country)
		if domains:
			print(create_csv(idx, domains))
	_exit(0)
if __name__ == '__main__':
	main()
