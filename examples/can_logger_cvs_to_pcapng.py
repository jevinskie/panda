#!/usr/bin/env python3

import argparse
import csv
import os
import struct
import sys
import typing

import pcapng.blocks as blocks
from pcapng.writer import FileWriter
from pcapng.utils import pack_timestamp_resolution


def csv_to_pcapng(in_file: typing.IO[str], out_file: typing.IO[bytes]) -> None:
    try:
        created_time = os.stat(in_file.fileno()).st_ctime
    except (OSError, AttributeError):
        created_time = 0.0

    shb = blocks.SectionHeader(
        options={
            "shb_hardware": "comma.ai panda",
            "shb_userappl": "can_logger.py",
        }
    )

    ts_resol = pack_timestamp_resolution(10, -6)

    # csv_rdr = csv.DictReader(in_file)
    # first_pkt_time = float(next(csv_rdr)["Time"])
    # in_file.seek(0)
    csv_rdr = csv.DictReader(in_file)
    if_tsoffset = int(created_time)
    ts_offset_frac = created_time - if_tsoffset

    for i in range(3):
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=227,  # LINKTYPE_CAN_SOCKETCAN
            options={
                "if_description": f"can{i}",
                "if_tsresol": ts_resol,
                "if_tsoffset": if_tsoffset,
            },
        )

    writer = FileWriter(out_file, shb)

    num_pkt = [0, 0, 0]

    last_ts = [0.0, 0.0, 0.0]

    for msg in csv_rdr:
        pkt_bytes = bytearray()
        msg_id = int(msg["MessageID"], 16)
        pkt_can_id = struct.pack('!I', msg_id)
        pkt_bytes += pkt_can_id
        pkt_data = bytes.fromhex(msg["Message"][2:])
        pkt_data_len = len(pkt_data)
        assert pkt_data_len == int(msg["MessageLength"])
        pkt_can_dlc = struct.pack('B', pkt_data_len)
        pkt_bytes += pkt_can_dlc
        pkt_bytes += b"\0\0\0"  # __pad, __res0, len8_dlc
        pkt_bytes += pkt_data + (b"\0" * (pkt_data_len - 8))
        epb = shb.new_member(blocks.EnhancedPacket)
        bus = int(msg["Bus"])
        epb.interface = bus
        num_pkt[bus] += 1
        epb.packet_data = pkt_bytes
        ts = float(msg["Time"]) + ts_offset_frac
        last_ts[bus] = ts
        epb.timestamp = ts
        writer.write_block(epb)


    for i in range(3):
        ifstat = shb.new_member(blocks.InterfaceStatistics)
        ifstat.timestamp = last_ts[i]
        ifstat.isb_ifrecv = num_pkt[i]
        writer.write_block(ifstat)


def real_main(args: argparse.Namespace) -> int:
    csv_to_pcapng(args.in_file, args.out_file)
    return 0


def get_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--in-file", type=argparse.FileType("r"), required=True, help="Input CSV file.")
    parser.add_argument("-o", "--out-file", type=argparse.FileType("wb"), required=True, help="Output pcapng file.")
    return parser


def main() -> int:
    try:
        arg_parser = get_arg_parser()
        args = arg_parser.parse_args()
        return real_main(args)
    except Exception as e:
        print(f"Got exception: {e}")
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
