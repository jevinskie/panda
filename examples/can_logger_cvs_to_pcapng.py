#!/usr/bin/env python2

from __future__ import print_function

import binascii
import csv
import struct
import sys

import pcapng.block
import pcapng.linktype
import pcapng.option

csv_in_path = sys.argv[1]
pcapng_out_path = sys.argv[2]

with open(csv_in_path, 'r') as csv_in, \
	open(pcapng_out_path, 'wb') as pcapng_out:

	csv_rdr = csv.DictReader(csv_in)

	shb_opts = []
	shb_obj = pcapng.block.SectionHeaderBlock(shb_opts)
	pcapng_out.write(shb_obj.pack())

	for i in range(3):
		idb_opts = [pcapng.option.IdbName('can{}'.format(i))]
		idb_obj = pcapng.block.InterfaceDescBlock(pcapng.linktype.LINKTYPE_CAN_SOCKETCAN, idb_opts)
		pcapng_out.write(idb_obj.pack())

	for msg in csv_rdr:
		pkt_bytes = b''
		msg_id = int(msg['MessageID'], 16)
		pkt_can_id = struct.pack('!I', msg_id)
		pkt_bytes += pkt_can_id
		pkt_data = binascii.unhexlify(msg['Message'][2:])
		pkt_can_dlc = struct.pack('B', len(pkt_data))
		pkt_bytes += pkt_can_dlc
		pkt_bytes += b'\0' * 3 # padding to 8 byte alignment
		pkt_bytes += pkt_data
		epb = pcapng.block.EnhancedPacketBlock(int(msg['Bus']), pkt_bytes, len(pkt_bytes), [])
		pcapng_out.write(epb.pack())

