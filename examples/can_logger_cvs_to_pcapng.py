#!/usr/bin/env python3

import argparse
import csv
import struct
import sys
import typing

import pcapng.blocks as blocks
from pcapng.writer import FileWriter

def csv_to_pcapng(in_file: typing.IO[str], out_file: typing.IO[bytes]) -> None:
    csv_rdr = csv.DictReader(in_file)

    shb = blocks.SectionHeader(
        options={
            "shb_hardware": "artificial",
            "shb_os": "python",
            "shb_userappl": "python-pcapng",
        }
    )

    for i in range(3):
        shb.new_member(
            blocks.InterfaceDescription,
            link_type=227,  # LINKTYPE_CAN_SOCKETCAN
            options={
                "if_description": f"can{i}",
                "if_os": "Python",
            },
        )

    writer = FileWriter(out_file, shb)

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
        epb.interface = int(msg["Bus"])
        epb.packet_data = pkt_bytes
        epb.timestamp = float(msg["Time"])
        writer.write_block(epb)


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
