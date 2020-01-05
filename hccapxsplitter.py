#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Abdelhafidh Belalia (s77rt)"
__license__ = "MIT"
__maintainer__ = "Abdelhafidh Belalia (s77rt)"
__email__ = "admin@abdelhafidh.com"
__version__ = "0.1.0"
__github__ = "https://github.com/s77rt/hccapxsplitter/"

import os
import argparse
import errno
import re
import gzip
from operator import itemgetter
from itertools import groupby

### Constants ###
HCCAPX_SIGNATURE = b'HCPX'
###

### H-Functions ###
def get_valid_filename(s, r='_'):
	s = str(s).strip().replace(' ', '_')
	return re.sub(r'(?u)[^-\w.\@]', r, s)
def xprint(text="", end='\n', flush=True):
	print(text, end=end, flush=flush)
###

### Database-Like ###
class hccapxs(list):
	def __init__(self):
		list.__init__(self)

class Database(object):
	def __init__(self):
		super(Database, self).__init__()
		self.hccapxs = hccapxs()
	def hccapx_add(self, bssid, essid, raw_data):
		self.hccapxs.append({ \
			'bssid': bssid, \
			'essid': essid, \
			'raw_data': raw_data \
		})
	def hccapx_groupby(self, group_by):
		if group_by == "handshake":
			self.hccapxs = [{'key': v['bssid']+"_"+str(k), 'raw_data': [v['raw_data']]} for k, v in enumerate(self.hccapxs)]
		else:
			self.hccapxs.sort(key=itemgetter(group_by))
			self.hccapxs = groupby(self.hccapxs, key=itemgetter(group_by))
			self.hccapxs = [{'key': k, 'raw_data': [x['raw_data'] for x in v]} for k, v in self.hccapxs]
DB = Database()
###

######################### CORE #########################

def read_file(file):
	if file.lower().endswith('.gz'):
		return gzip.open(file, 'rb')
	return open(file, 'rb')

def read_hccapx(hccapx_file, hccapx_size=393):
	def extract_bssid(raw_data):
		bssid = raw_data[59:65].hex()
		bssid = '-'.join(bssid[i:i+2] for i in range(0,12,2))
		bssid = bssid.upper()
		return bssid
	def extract_essid(raw_data):
		essid = raw_data[10:10+raw_data[9]]
		essid = str(essid.decode(encoding='utf-8', errors='ignore').rstrip('\x00'))
		return essid
	while True: 
		hccapx = hccapx_file.read(hccapx_size) 
		if hccapx and hccapx[0:4] == HCCAPX_SIGNATURE:
			DB.hccapx_add(extract_bssid(hccapx), extract_essid(hccapx), hccapx)
		else:
			return

######################### MAIN #########################

def main():
	if os.path.isfile(args.input):
		hccapx_file =  read_file(args.input)
		read_hccapx(hccapx_file)
		DB.hccapx_groupby(args.group_by)
		if len(DB.hccapxs):
			written = 0
			xprint("\nOutput hccapx files:")
			for hccapx in DB.hccapxs:
				if args.output:
					hccapx_filename = (re.sub('\\.hccap(x?)$', '', args.output, flags=re.IGNORECASE)) + get_valid_filename("{}.hccapx".format("_"+str(hccapx['key']) if hccapx['key'] != "none" else ''))
				else:
					hccapx_filename = get_valid_filename("{}.hccapx".format(str(hccapx['key'])))
				print(hccapx_filename)
				hccapx_file = open(hccapx_filename, 'wb')
				hccapx_file.write(b''.join(hccapx['raw_data']))
				hccapx_file.close()
				written += len(hccapx['raw_data'])
			if written:
				xprint("\nWritten {} WPA Handshakes to {} files".format(written, len(DB.hccapxs)), end='')
		xprint()
	else:
		xprint(FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), args.input))
		exit()

#########################
#########################

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Tool to split one big hccapx file to multiple hccapx files', add_help=False)
	required = parser.add_argument_group('required arguments')
	optional = parser.add_argument_group('optional arguments')
	required.add_argument("--input", "-i", help="Input hccapx file", metavar="capture.hccapx", required=True)
	optional.add_argument("--output", "-o", help="Output file", metavar="capture.hccapx")
	optional.add_argument("--group-by", "-g", choices=['bssid', 'essid', 'handshake'], default='bssid')
	optional.add_argument("--quiet", "-q", help="Enable quiet mode (print only output files)", action="store_true")
	optional.add_argument("--version", "-v", action='version', version=__version__)
	optional.add_argument("--help", "-h", action='help', default=argparse.SUPPRESS,	help='show this help message and exit')
	args = parser.parse_args()
	if args.quiet:
		def xprint(text="", end='\n', flush=True):
			pass
	main()
